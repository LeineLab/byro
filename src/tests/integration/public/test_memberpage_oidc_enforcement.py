import pytest
from django.test import override_settings
from django.urls import reverse

OIDC_ON = dict(
    OIDC_ISSUER_URL="https://issuer.example",
    OIDC_CLIENT_ID="client",
    OIDC_ENFORCE_MEMBERPAGE_LOGIN=True,
)


def dashboard_url(member):
    return reverse(
        "public:memberpage:member.dashboard",
        kwargs={"secret_token": member.profile_memberpage.secret_token},
    )


@pytest.mark.django_db
def test_token_only_allowed_when_flag_disabled(
    member, membership, client, configuration
):
    # Default behaviour: no enforcement, token is enough.
    response = client.get(dashboard_url(member))
    assert response.status_code == 200


@pytest.mark.django_db
@override_settings(**OIDC_ON)
def test_token_only_blocked_when_enforced(member, membership, client, configuration):
    response = client.get(dashboard_url(member))
    assert response.status_code == 302
    assert response.url == reverse("common:oidc-login")


@pytest.mark.django_db
@override_settings(**OIDC_ON)
def test_matching_oidc_session_allowed(member, membership, client, configuration):
    session = client.session
    session["oidc_member_email"] = member.email
    session.save()
    response = client.get(dashboard_url(member))
    assert response.status_code == 200


@pytest.mark.django_db
@override_settings(**OIDC_ON)
def test_matching_oidc_session_case_insensitive(
    member, membership, client, configuration
):
    session = client.session
    session["oidc_member_email"] = member.email.upper()
    session.save()
    response = client.get(dashboard_url(member))
    assert response.status_code == 200


@pytest.mark.django_db
@override_settings(**OIDC_ON)
def test_foreign_oidc_session_blocked(member, membership, client, configuration):
    session = client.session
    session["oidc_member_email"] = "someone-else@example.com"
    session.save()
    response = client.get(dashboard_url(member))
    assert response.status_code == 302
    assert response.url == reverse("common:oidc-login")


@pytest.mark.django_db
@override_settings(**OIDC_ON)
def test_office_login_bypasses_enforcement(
    member, membership, logged_in_client, configuration
):
    response = logged_in_client.get(dashboard_url(member))
    assert response.status_code == 200


@pytest.mark.django_db
@override_settings(
    OIDC_ISSUER_URL="",
    OIDC_CLIENT_ID="",
    OIDC_ENFORCE_MEMBERPAGE_LOGIN=True,
)
def test_enforcement_noop_without_oidc_configured(
    member, membership, client, configuration
):
    # Flag on but OIDC not configured: cannot enforce, fall back to token access.
    response = client.get(dashboard_url(member))
    assert response.status_code == 200


@pytest.mark.django_db
@override_settings(**OIDC_ON)
def test_member_list_blocked_when_enforced(member, membership, client, configuration):
    response = client.get(
        reverse(
            "public:memberpage:member.list",
            kwargs={"secret_token": member.profile_memberpage.secret_token},
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("common:oidc-login")
