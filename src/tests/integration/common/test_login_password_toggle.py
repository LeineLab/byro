import pytest
from django.test import override_settings
from django.urls import reverse

OIDC_ON = dict(OIDC_ISSUER_URL="https://issuer.example", OIDC_CLIENT_ID="client")


@pytest.mark.django_db
@override_settings(OIDC_DISABLE_PASSWORD_LOGIN=True, **OIDC_ON)
def test_get_login_redirects_to_idp_when_password_disabled(client, configuration):
    response = client.get(reverse("common:login"))
    assert response.status_code == 302
    assert response.url == reverse("common:oidc-login")


@pytest.mark.django_db
@override_settings(OIDC_DISABLE_PASSWORD_LOGIN=True, **OIDC_ON)
def test_post_login_redirects_to_idp_when_password_disabled(client, configuration):
    response = client.post(reverse("common:login"), {"username": "x", "password": "y"})
    assert response.status_code == 302
    assert response.url == reverse("common:oidc-login")


@pytest.mark.django_db
@override_settings(OIDC_DISABLE_PASSWORD_LOGIN=True, **OIDC_ON)
def test_login_page_shown_after_sso_error(client, configuration):
    # After a failed SSO attempt the page is rendered (with the SSO button) instead
    # of looping back to the IdP; the password form stays hidden.
    response = client.get(reverse("common:login") + "?sso_error=1")
    content = response.content.decode()
    assert response.status_code == 200
    assert 'name="password"' not in content
    assert "SSO" in content


@pytest.mark.django_db
@override_settings(
    OIDC_ISSUER_URL="", OIDC_CLIENT_ID="", OIDC_DISABLE_PASSWORD_LOGIN=True
)
def test_password_login_not_disabled_without_oidc(client, configuration):
    # The flag has no effect unless OIDC is configured, so nobody is locked out.
    response = client.get(reverse("common:login"))
    assert response.status_code == 200
    assert 'name="password"' in response.content.decode()


@pytest.mark.django_db
def test_default_login_shows_password_form(client, configuration):
    response = client.get(reverse("common:login"))
    assert response.status_code == 200
    assert 'name="password"' in response.content.decode()


@pytest.mark.django_db
@override_settings(OIDC_DISABLE_PASSWORD_LOGIN=True, **OIDC_ON)
def test_logout_does_not_auto_redirect_to_idp(client, configuration):
    # Logout lands on the login page (with the SSO button); it must not bounce
    # straight back to the IdP, which would silently log the user in again.
    response = client.get(reverse("common:logout"))
    assert response.status_code == 302
    assert response.url == reverse("common:login") + "?loggedout=1"

    page = client.get(response.url)
    assert page.status_code == 200
    assert "SSO" in page.content.decode()
