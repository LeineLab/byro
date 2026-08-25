import collections.abc
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.db.models import Q
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django.views.generic import DetailView, ListView
from django.views.generic.edit import FormMixin

from byro.bookkeeping.models import Booking
from byro.bookkeeping.special_accounts import SpecialAccounts
from byro.common.models.configuration import Configuration, MemberViewLevel
from byro.common.oidc import is_oidc_configured
from byro.members.models import Member
from byro.office.signals import member_dashboard_tile
from byro.public.forms import MemberChangeProposalForm, PrivacyConsentForm


class OIDCMemberPageMixin:
    """Optionally require a matching OIDC login to view a member page.

    When OIDC_ENFORCE_MEMBERPAGE_LOGIN is enabled (and OIDC is configured) the
    secret token alone no longer grants access: the visitor must either be logged
    into the office backend, or hold an OIDC session whose verified email matches
    the member's email. Otherwise they are sent to the OIDC login, which routes
    them to their own member page."""

    def dispatch(self, request, *args, **kwargs):
        denied = self.enforce_oidc_login(request, kwargs.get("secret_token"))
        if denied is not None:
            return denied
        return super().dispatch(request, *args, **kwargs)

    def enforce_oidc_login(self, request, secret_token):
        if not (settings.OIDC_ENFORCE_MEMBERPAGE_LOGIN and is_oidc_configured()):
            return None
        # Office staff (backend login) may always open member pages.
        if request.user.is_authenticated:
            return None
        member = Member.all_objects.filter(
            profile_memberpage__secret_token=secret_token
        ).first()
        if member is None:
            # Unknown token: let the view raise its usual 404, don't leak here.
            return None
        session_email = request.session.get("oidc_member_email")
        if (
            session_email
            and member.email
            and session_email.casefold() == member.email.casefold()
        ):
            return None
        return redirect("common:oidc-login")


class MemberBaseView(OIDCMemberPageMixin, DetailView):
    slug_field = "profile_memberpage__secret_token"
    slug_url_kwarg = "secret_token"

    model = Member


class MemberView(FormMixin, MemberBaseView):
    template_name = "public/members/dashboard.html"
    form_class = PrivacyConsentForm

    def get_bookings(self, member):
        account_list = [SpecialAccounts.donations, SpecialAccounts.fees_receivable]
        return (
            Booking.objects.with_transaction_data()
            .filter(
                Q(debit_account__in=account_list) | Q(credit_account__in=account_list),
                member=member,
                transaction__value_datetime__lte=now(),
            )
            .order_by("-transaction__value_datetime")
        )

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)
        obj = context["member"]
        config = Configuration.get_solo()

        context["config"] = config
        context["bookings"] = self.get_bookings(obj)
        context["member_view_level"] = MemberViewLevel
        context["proposal_form"] = MemberChangeProposalForm(member=obj)
        context["pending_proposals"] = obj.change_proposals.all()

        _now = now()
        memberships = obj.memberships.order_by("-start").all()
        if not memberships:
            return context

        member_fields = obj.get_fields()
        for field in context["form"]:
            field.meta = (
                member_fields[field.name].getter(obj)
                if field.name in member_fields
                else ""
            ) or ""
        first = memberships[0].start
        delta = timedelta()
        for ms in memberships:
            delta += (ms.end or _now.date()) - ms.start
            if not ms.end or ms.end <= _now.date():
                context["current_membership"] = ms
        context["memberships"] = memberships
        context["member_since"] = {
            "days": int(delta.total_seconds() / (60 * 60 * 24)),
            "years": int(round(delta.days / 365, 1)),
            "first": first,
        }
        context["tiles"] = []
        for __, response in member_dashboard_tile.send(self.request, member=obj):
            if not response:
                continue
            if isinstance(response, collections.abc.Mapping) and response.get(
                "public", False
            ):
                context["tiles"].append(response)
        return context

    def get_form_kwargs(self, *args, **kwargs):
        result = super().get_form_kwargs(*args, **kwargs)
        result["member"] = self.get_object()
        return result

    def get_success_url(self):
        return reverse(
            "public:memberpage:member.dashboard",
            kwargs={"secret_token": self.kwargs["secret_token"]},
        )

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = self.get_form()
        if form.is_valid():
            form.save()
        return HttpResponseRedirect(self.get_success_url())


class MemberProposeView(MemberBaseView):
    """Handles the member's data-change proposal form. Proposals are stored for
    later admin review and never modify member data directly."""

    def post(self, request, *args, **kwargs):
        member = self.get_object()
        form = MemberChangeProposalForm(request.POST, member=member)
        if form.is_valid():
            form.save()
            messages.success(
                request,
                _(
                    "Thank you! Your proposed changes were submitted and will be "
                    "reviewed by an administrator."
                ),
            )
        else:
            messages.error(request, _("Your proposed changes could not be saved."))
        return redirect(
            "public:memberpage:member.dashboard",
            secret_token=self.kwargs["secret_token"],
        )


class MemberListView(OIDCMemberPageMixin, ListView):
    template_name = "public/members/memberlist.html"
    paginate_by = 50
    context_object_name = "members"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)
        config = Configuration.get_solo()
        context["config"] = config
        context["member_view_level"] = MemberViewLevel
        context["member_undisclosed"] = (
            Member.objects.with_active_membership()
            .exclude(profile_memberpage__is_visible_to_members=True)
            .count()
        )
        return context

    def get_queryset(self):
        secret_token = self.kwargs.get("secret_token")
        if not secret_token:
            raise Http404("Page does not exist")

        member = Member.all_objects.filter(
            profile_memberpage__secret_token=secret_token
        ).first()
        if not member:
            raise Http404("Page does not exist")

        if not member.is_active:
            raise Http404("Page does not exist")

        # Only list members with a current active membership; former members
        # (membership ended) are hidden even if they once consented to sharing.
        return Member.objects.with_active_membership().filter(
            profile_memberpage__is_visible_to_members=True
        )
