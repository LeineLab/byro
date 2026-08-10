import pytest
from django.urls import reverse


def _member_dashboard_url(member):
    return reverse(
        "public:memberpage:member.dashboard",
        kwargs={"secret_token": member.profile_memberpage.secret_token},
    )


def _set_member_session(client, email):
    session = client.session
    session["oidc_member_email"] = email
    session.save()


@pytest.mark.django_db
def test_member_home_redirects_to_own_page(member, client, configuration):
    _set_member_session(client, member.email)
    response = client.get(reverse("common:member-home"))
    assert response.status_code == 302
    assert response.url == _member_dashboard_url(member)


@pytest.mark.django_db
def test_member_home_clears_stale_email(client, configuration):
    _set_member_session(client, "nobody@example.com")
    response = client.get(reverse("common:member-home"))
    assert response.status_code == 302
    assert response.url == reverse("common:login")
    assert "oidc_member_email" not in client.session


@pytest.mark.django_db
def test_login_page_redirects_member_to_own_page(member, client, configuration):
    _set_member_session(client, member.email)
    response = client.get(reverse("common:login"))
    assert response.status_code == 302
    assert response.url == reverse("common:member-home")


@pytest.mark.django_db
def test_protected_page_redirects_member_to_member_home(member, client, configuration):
    _set_member_session(client, member.email)
    # "/" is the office dashboard, which anonymous users cannot see.
    response = client.get("/")
    assert response.status_code == 302
    assert response.url == reverse("common:member-home")


@pytest.mark.django_db
def test_anonymous_without_session_still_redirected_to_login(client, configuration):
    response = client.get("/")
    assert response.status_code == 302
    assert response.url.startswith(reverse("common:login"))


@pytest.mark.django_db
def test_logout_clears_member_session(member, client, configuration):
    _set_member_session(client, member.email)
    response = client.get(reverse("common:logout"))
    assert response.status_code == 302
    assert response.url == reverse("common:login") + "?loggedout=1"
    assert "oidc_member_email" not in client.session
