from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse

from byro.common import oidc

# --- oidc.is_admin ------------------------------------------------------------


@override_settings(OIDC_ADMIN_GROUP="")
def test_is_admin_without_admin_group_returns_true():
    assert oidc.is_admin({}, "access-token") is True


@override_settings(OIDC_ADMIN_GROUP="admins")
def test_is_admin_with_group_in_claims():
    assert oidc.is_admin({"groups": ["users", "admins"]}, "access-token") is True
    assert oidc.is_admin({"groups": ["users"]}, "access-token") is False


@override_settings(OIDC_ADMIN_GROUP="admins")
def test_is_admin_with_space_separated_groups():
    assert oidc.is_admin({"groups": "users admins"}, "access-token") is True


@override_settings(OIDC_ADMIN_GROUP="admins")
def test_is_admin_falls_back_to_userinfo():
    with patch.object(oidc, "get_userinfo", return_value={"groups": ["admins"]}) as m:
        assert oidc.is_admin({}, "access-token") is True
    m.assert_called_once_with("access-token")


# --- oidc.get_verified_email --------------------------------------------------


def test_get_verified_email_from_claims():
    claims = {"email": "joe@hacker.space", "email_verified": True}
    assert oidc.get_verified_email(claims, "access-token") == "joe@hacker.space"


def test_get_verified_email_rejects_unverified():
    claims = {"email": "joe@hacker.space", "email_verified": False}
    with pytest.raises(oidc.OIDCError):
        oidc.get_verified_email(claims, "access-token")


def test_get_verified_email_requires_email():
    with patch.object(oidc, "get_userinfo", return_value={}):
        with pytest.raises(oidc.OIDCError):
            oidc.get_verified_email({}, "access-token")


def test_get_verified_email_falls_back_to_userinfo():
    userinfo = {"email": "joe@hacker.space", "email_verified": True}
    with patch.object(oidc, "get_userinfo", return_value=userinfo):
        assert oidc.get_verified_email({}, "access-token") == "joe@hacker.space"


# --- OIDCCallbackView redirect behaviour --------------------------------------


def _callback(client):
    session = client.session
    session["oidc_state"] = "state"
    session["oidc_nonce"] = "nonce"
    session.save()
    return client.get(
        reverse("common:oidc-callback"), {"state": "state", "code": "code"}
    )


@pytest.mark.django_db
@override_settings(
    OIDC_ISSUER_URL="https://issuer.example",
    OIDC_CLIENT_ID="client",
    OIDC_ADMIN_GROUP="admins",
)
@patch(
    "byro.common.views.exchange_code",
    return_value={"id_token": "tok", "access_token": "at"},
)
def test_callback_non_admin_redirects_to_memberpage(mock_exchange, member, client):
    claims = {"email": member.email, "email_verified": True, "groups": ["users"]}
    with patch("byro.common.views.validate_id_token", return_value=claims):
        response = _callback(client)

    assert response.status_code == 302
    expected = reverse(
        "public:memberpage:member.dashboard",
        kwargs={"secret_token": member.profile_memberpage.secret_token},
    )
    assert response.url == expected
    # non-admin must not be logged into the office backend
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
@override_settings(
    OIDC_ISSUER_URL="https://issuer.example",
    OIDC_CLIENT_ID="client",
    OIDC_ADMIN_GROUP="admins",
)
@patch(
    "byro.common.views.exchange_code",
    return_value={"id_token": "tok", "access_token": "at"},
)
def test_callback_non_admin_unknown_email_shows_error(mock_exchange, client):
    claims = {
        "email": "stranger@example.com",
        "email_verified": True,
        "groups": ["users"],
    }
    with patch("byro.common.views.validate_id_token", return_value=claims):
        response = _callback(client)

    assert response.status_code == 302
    assert response.url == reverse("common:login")


@pytest.mark.django_db
@override_settings(
    OIDC_ISSUER_URL="https://issuer.example",
    OIDC_CLIENT_ID="client",
    OIDC_ADMIN_GROUP="admins",
    OIDC_AUTO_CREATE_ACCOUNT=True,
    OIDC_USERNAME_FIELD="preferred_username",
)
@patch(
    "byro.common.views.exchange_code",
    return_value={"id_token": "tok", "access_token": "at"},
)
def test_callback_admin_logs_into_office(mock_exchange, client):
    claims = {
        "email": "boss@hacker.space",
        "email_verified": True,
        "groups": ["admins"],
        "preferred_username": "boss",
    }
    with patch("byro.common.views.validate_id_token", return_value=claims):
        response = _callback(client)

    assert response.status_code == 302
    assert response.url == "/"
    assert "_auth_user_id" in client.session


@pytest.mark.django_db
@override_settings(
    OIDC_ISSUER_URL="https://issuer.example",
    OIDC_CLIENT_ID="client",
    OIDC_ADMIN_GROUP="admins",
    OIDC_AUTO_CREATE_ACCOUNT=True,
    OIDC_USERNAME_FIELD="preferred_username",
)
@patch(
    "byro.common.views.exchange_code",
    return_value={"id_token": "tok", "access_token": "at"},
)
def test_callback_non_admin_creates_no_account_with_auto_create(
    mock_exchange, member, client
):
    # With auto_create_account on, a user WITHOUT the admin group must not get a
    # local (admin) account created; they are routed to their member page.
    User = get_user_model()
    before = User.objects.count()
    claims = {
        "email": member.email,
        "email_verified": True,
        "groups": ["users"],
        "preferred_username": "not-an-admin",
    }
    with patch("byro.common.views.validate_id_token", return_value=claims):
        response = _callback(client)

    assert response.status_code == 302
    assert response.url == reverse(
        "public:memberpage:member.dashboard",
        kwargs={"secret_token": member.profile_memberpage.secret_token},
    )
    assert User.objects.count() == before
    assert not User.objects.filter(username="not-an-admin").exists()
    assert "_auth_user_id" not in client.session
