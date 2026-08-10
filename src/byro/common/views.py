import secrets
import urllib

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.http import Http404, HttpRequest, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django.views.generic import TemplateView, View

from byro.common.models import LogEntry
from byro.common.oidc import (
    OIDCError,
    build_auth_url,
    exchange_code,
    get_or_create_user,
    get_verified_email,
    is_admin,
    is_oidc_configured,
    validate_id_token,
)
from byro.members.models import Member


def oidc_redirect_uri():
    """Build the OIDC callback URL from the configured SITE_URL rather than the
    incoming request. This keeps the redirect_uri byte-for-byte identical between
    the authorization request and the token exchange, and uses the correct scheme
    (https) even when byro sits behind a TLS-terminating proxy that Django is not
    told about. It must match the redirect URI registered in the OIDC provider."""
    return urllib.parse.urljoin(settings.SITE_URL, reverse("common:oidc-callback"))


def member_home(request: HttpRequest) -> HttpResponseRedirect:
    """Send a member with an active OIDC session to their own member page.

    Members are not Django-authenticated; their session only carries the verified
    email set during the OIDC callback. If the email no longer maps to a member,
    the stale marker is dropped so we fall back to the login page without looping.
    """
    email = request.session.get("oidc_member_email")
    if email:
        member = Member.objects.filter(email__iexact=email).first()
        if member:
            return redirect(
                "public:memberpage:member.dashboard",
                secret_token=member.profile_memberpage.secret_token,
            )
        request.session.pop("oidc_member_email", None)
    return redirect("common:login")


def password_login_disabled():
    """Whether the username/password login is turned off in favour of OIDC. Only
    takes effect while OIDC is configured, so a misconfiguration cannot lock
    everyone out."""
    return bool(settings.OIDC_DISABLE_PASSWORD_LOGIN and is_oidc_configured())


def sso_error_redirect():
    """Redirect back to the login page after a failed SSO attempt, marked so the
    page is shown (with the error) instead of immediately bouncing to the IdP
    again when password login is disabled."""
    return redirect(f"{reverse('common:login')}?sso_error=1")


class LoginView(TemplateView):
    template_name = "common/auth/login.html"

    def get(self, request, *args, **kwargs):
        # A member with an active OIDC session should land on their member page,
        # not on the login mask again.
        if request.session.get("oidc_member_email"):
            return redirect("common:member-home")
        # Optionally skip the password login form and go straight to the identity
        # provider. Still render the page after a failed SSO attempt
        # (?sso_error=1) so the error is shown instead of looping to the IdP.
        if password_login_disabled() and "sso_error" not in request.GET:
            return redirect("common:oidc-login")
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["oidc_enabled"] = is_oidc_configured()
        ctx["password_login_enabled"] = not password_login_disabled()
        return ctx

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponseRedirect:
        if password_login_disabled():
            return redirect("common:oidc-login")
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(username=username, password=password)

        if user is None:
            messages.error(
                request, _("No user account matches the entered credentials.")
            )
            return redirect("common:login")

        if not user.is_active:
            messages.error(request, _("User account is deactivated."))
            LogEntry.objects.create(
                content_object=user,
                user=user,
                action_type="byro.common.login.deactivated",
            )
            return redirect("common:login")

        # Start a fresh session so a re-login invalidates all previous session
        # values (e.g. a member marker from an earlier OIDC login).
        request.session.flush()
        login(request, user)
        LogEntry.objects.create(
            content_object=user, user=user, action_type="byro.common.login.success"
        )
        url = urllib.parse.unquote(request.GET.get("next", ""))
        if url and url_has_allowed_host_and_scheme(url, request.get_host()):
            return redirect(url)

        return redirect("/")


def logout_view(request: HttpRequest) -> HttpResponseRedirect:
    if request.user.is_authenticated:
        LogEntry.objects.create(
            content_object=request.user,
            user=request.user,
            action_type="byro.common.logout",
        )
    # Flushes the session, which also clears a member's OIDC session marker
    # (oidc_member_email).
    logout(request)
    return redirect("common:login")


class LogInfoView(TemplateView):
    template_name = "common/log/info.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)
        context["log_head"] = LogEntry.objects.get_chain_end()
        context["now"] = now()
        return context


class OIDCLoginView(View):
    def get(self, request):
        if not is_oidc_configured():
            raise Http404
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        request.session["oidc_state"] = state
        request.session["oidc_nonce"] = nonce
        redirect_uri = oidc_redirect_uri()
        try:
            auth_url = build_auth_url(redirect_uri, state, nonce)
        except OIDCError as e:
            messages.error(request, str(e))
            return sso_error_redirect()
        return HttpResponseRedirect(auth_url)


class OIDCCallbackView(View):
    def get(self, request):
        if not is_oidc_configured():
            raise Http404

        error = request.GET.get("error")
        if error:
            error_description = request.GET.get("error_description", error)
            messages.error(
                request, _("SSO login failed: %(error)s") % {"error": error_description}
            )
            return sso_error_redirect()

        try:
            state = request.GET.get("state", "")
            if not state or not secrets.compare_digest(
                state, request.session.get("oidc_state", "")
            ):
                raise OIDCError("Invalid or missing state parameter")

            code = request.GET.get("code")
            if not code:
                raise OIDCError("Missing authorization code")

            nonce = request.session.pop("oidc_nonce", "")
            request.session.pop("oidc_state", None)
            # Persist the consumed state immediately (Django would otherwise only
            # save the session at the end of the request). This closes the race
            # window in which a duplicate callback request -- e.g. from browser
            # prefetch -- would still pass the state check and redeem the
            # single-use authorization code a second time.
            request.session.save()
            redirect_uri = oidc_redirect_uri()

            token_response = exchange_code(code, redirect_uri)
            id_token = token_response.get("id_token")
            if not id_token:
                raise OIDCError("No id_token in token response")

            claims = validate_id_token(id_token, nonce)
            access_token = token_response.get("access_token", "")

            if not is_admin(claims, access_token):
                return self.redirect_to_memberpage(request, claims, access_token)

            user = get_or_create_user(claims, access_token)

            if not user.is_active:
                messages.error(request, _("User account is deactivated."))
                return sso_error_redirect()

            # Start a fresh session so a re-login invalidates all previous
            # session values (e.g. a member marker left over after ending an
            # impersonation), and the admin reliably gets office access.
            request.session.flush()
            user.backend = "django.contrib.auth.backends.ModelBackend"
            login(request, user)
            LogEntry.objects.create(
                content_object=user,
                user=user,
                action_type="byro.common.login.oidc",
            )
            url = urllib.parse.unquote(request.GET.get("next", ""))
            if url and url_has_allowed_host_and_scheme(url, request.get_host()):
                return redirect(url)
            return redirect("/")

        except OIDCError as e:
            messages.error(request, str(e))
            return sso_error_redirect()

    def redirect_to_memberpage(self, request, claims, access_token):
        """Send a non-admin user to their own member page based on their email."""
        email = get_verified_email(claims, access_token)
        member = Member.objects.filter(email__iexact=email).first()
        if member is None:
            messages.error(
                request,
                _("No member was found for the email address %(email)s.")
                % {"email": email},
            )
            return sso_error_redirect()
        # Start a fresh session (drops any previous Django auth or stale markers,
        # so a re-login fully invalidates the prior session), then record the
        # verified email so enforced member pages can match it.
        logout(request)
        request.session["oidc_member_email"] = email
        return redirect(
            "public:memberpage:member.dashboard",
            secret_token=member.profile_memberpage.secret_token,
        )
