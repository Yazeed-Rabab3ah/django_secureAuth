from django.db.models.base import Model as Model
from django.db.models.query import QuerySet
from django.shortcuts import get_object_or_404, render ,redirect
from django.http import HttpResponse, HttpResponseNotAllowed, HttpResponseRedirect
from django.urls import reverse_lazy

from .forms import *
from django.contrib.auth.models import auth
from django.contrib.auth import authenticate ,login 
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from django.views.generic import TemplateView 
from django.views.generic import CreateView, ListView, UpdateView, DeleteView
from django.contrib.auth.views import LoginView ,LogoutView, logout_then_login

from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin, AccessMixin ,UserPassesTestMixin
from django.utils.timezone import now ,make_aware
from django.views.generic import FormView
from .utils import send_otp
from .forms import OTPForm, LoginForm
import pyotp
from datetime import datetime 


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


class MyLoginView(FormView):
    form_class = LoginForm
    template_name = 'my-login.html'
    success_url = reverse_lazy('otp-verify')  # Redirect to OTP verification page

    def form_valid(self, form):
        # Authenticate user with username and password
        user = form.get_user()
        if user:
            # Log the user in temporarily
            login(self.request, user)

            # Generate and send OTP
            send_otp(self.request)
            return redirect(self.get_success_url())
        return super().form_invalid(form)

class OTPVerificationView(FormView):
    form_class = OTPForm
    template_name = 'otp-verify.html'
    success_url = reverse_lazy('index')

    def form_valid(self, form):
        otp_entered = form.cleaned_data['otp']
        otp_secret_key = self.request.session.get('otp_secret_key')
        otp_valid_date = self.request.session.get('otp_valid_date')

        if not otp_secret_key or not otp_valid_date:
            form.add_error(None, "OTP expired or invalid.")
            return self.form_invalid(form)

        # Validate OTP
        totp = pyotp.TOTP(otp_secret_key, interval=60)
        try:
            # Convert otp_valid_date to an aware datetime
            otp_valid_date_aware = make_aware(datetime.fromisoformat(otp_valid_date))
        except ValueError:
            form.add_error(None, "Invalid OTP date format.")
            return self.form_invalid(form)

        # Compare aware datetimes
        if totp.verify(otp_entered) and now() <= otp_valid_date_aware:
            # OTP is valid
            return super().form_valid(form)

        # OTP is invalid
        form.add_error(None, "Invalid or expired OTP.")
        return self.form_invalid(form)


class ProfileManagementView(LoginRequiredMixin, TemplateView):
     template_name = 'profile/profile-management.html'
     login_url = 'my-login'

     def get_context_data(self, **kwargs):
         context = super().get_context_data(**kwargs)
         context["user"] = self.request.user
         context['username']=self.kwargs.get('username')
         print(f"Current User: {context['user']}, Username from URL: {context['username']}")
         return context
     
     
class UpdateUserView(LoginRequiredMixin, UpdateView):
     model = Member
     form_class = UpdateUserForm
     template_name = 'profile/update-user.html'
     success_url = reverse_lazy('profile-management',kwargs={'username': Member.username})
     login_url = 'my-login'

     def get_object(self,queryset=None):
          return self.request.user


class DeleteUserView(LoginRequiredMixin,DeleteView):
     model = Member
     template_name = 'profile/delete-user.html'
     success_url = reverse_lazy('my-login')
     login_url = 'my-login'

     def get_object(self, queryset=None):
          return self.request.user

class UserLogoutView(LoginRequiredMixin, LogoutView):
     next_page = reverse_lazy('index')

     def post(self, request, *args, **kwargs):
        if request.method != 'POST':
            return HttpResponseNotAllowed(['POST'])  # Will return a 405 error for any non-GET request for CSRF attacks 

        return super().post(request, *args, **kwargs)

class DashboardView(LoginRequiredMixin, TemplateView):
     template_name = 'profile/dashboard.html'
     login_url = 'my-login'
     context_data = {'username':Member.username}
     def get_object(self, queryset=None):
          return self.request.user






















