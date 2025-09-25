# views.py
from datetime import datetime

from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LogoutView
from django.http import HttpResponseNotAllowed
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.generic import (
    TemplateView, CreateView, UpdateView, DeleteView, FormView
)

import pyotp

from .forms import CreateUserForm, UpdateUserForm, OTPForm, LoginForm
from .models import Member
from .utils import send_otp  # see robust implementation below


User = get_user_model()


# -------------------------
# Public pages
# -------------------------

class HomeView(TemplateView):
    template_name = 'index.html'


class RegisterView(CreateView):
    form_class = CreateUserForm
    template_name = 'register.html'
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        form.save()
        messages.success(self.request, "The user is successfully added")
        return super().form_valid(form)


# -------------------------
# Login + OTP (2FA) flow
# -------------------------

class MyLoginView(FormView):
    """
    Step 1: Verify username/password with LoginForm, then
    generate+send OTP. Do NOT log the user in yet.
    """
    form_class = LoginForm
    template_name = 'my-login.html'
    success_url = reverse_lazy('otp-verify')  # OTP page

    def form_valid(self, form):
        user = form.get_user()
        if not user:
            return self.form_invalid(form)

        # Store user identity for the OTP step (no login yet)
        self.request.session['pre_2fa_user_id'] = user.pk
        self.request.session['pre_2fa_username'] = user.get_username()

        # Generate and send OTP, and store secret+expiry in session
        send_otp(self.request, user=user)

        return redirect(self.get_success_url())


class OTPVerificationView(FormView):
    """
    Step 2: Verify the OTP and expiry. If valid, log the user in.
    """
    form_class = OTPForm
    template_name = 'otp-verify.html'
    success_url = reverse_lazy('index')

    def form_valid(self, form):
        code_entered = form.cleaned_data['otp']

        # Required session keys
        otp_secret_key = self.request.session.get('otp_secret_key')
        raw_expiry = self.request.session.get('otp_valid_date')
        user_id = self.request.session.get('pre_2fa_user_id')

        if not (otp_secret_key and raw_expiry and user_id):
            form.add_error(None, "OTP expired or invalid.")
            return self.form_invalid(form)

        # Parse expiry from session
        if isinstance(raw_expiry, datetime):
            expires_at = raw_expiry
        else:
            # parse_datetime handles "Z" and timezone offsets
            expires_at = parse_datetime(raw_expiry)

        if not expires_at:
            form.add_error(None, "Invalid OTP date format.")
            return self.form_invalid(form)

        # Ensure aware
        if timezone.is_naive(expires_at):
            expires_at = timezone.make_aware(expires_at, timezone.get_default_timezone())

        # Verify OTP (allow a tiny clock skew if desired)
        totp = pyotp.TOTP(otp_secret_key, interval=60)
        is_valid_code = totp.verify(code_entered, valid_window=1)

        if is_valid_code and timezone.now() <= expires_at:
            # Fetch and log in the user
            try:
                user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                form.add_error(None, "User not found.")
                return self.form_invalid(form)

            login(self.request, user)

            # Clean session
            for k in ("otp_secret_key", "otp_valid_date", "pre_2fa_user_id", "pre_2fa_username"):
                self.request.session.pop(k, None)

            return super().form_valid(form)

        form.add_error(None, "Invalid or expired OTP.")
        return self.form_invalid(form)


# -------------------------
# Profile & account management
# -------------------------

class ProfileManagementView(LoginRequiredMixin, TemplateView):
    template_name = 'profile/profile-management.html'
    login_url = 'my-login'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["user"] = self.request.user
        context['username'] = self.kwargs.get('username')
        return context


class UpdateUserView(LoginRequiredMixin, UpdateView):
    model = Member
    form_class = UpdateUserForm
    template_name = 'profile/update-user.html'
    login_url = 'my-login'

    def get_object(self, queryset=None):
        return self.request.user

    def get_success_url(self):
        # Redirect back to the profile-management page for the current user
        return reverse('profile-management', kwargs={'username': self.request.user.username})


class DeleteUserView(LoginRequiredMixin, DeleteView):
    model = Member
    template_name = 'profile/delete-user.html'
    success_url = reverse_lazy('my-login')
    login_url = 'my-login'

    def get_object(self, queryset=None):
        return self.request.user


class UserLogoutView(LoginRequiredMixin, LogoutView):
    next_page = reverse_lazy('index')
    # If you want to force POST-only logout, uncomment the next line:
    # http_method_names = ['post']

    def post(self, request, *args, **kwargs):
        # If you enforce POST-only logout, Django calls post() only on POST.
        # The check below is redundant but harmless; keep or remove as you like.
        if request.method != 'POST':
            return HttpResponseNotAllowed(['POST'])
        return super().post(request, *args, **kwargs)


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'profile/dashboard.html'
    login_url = 'my-login'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['username'] = self.request.user.username
        return ctx
