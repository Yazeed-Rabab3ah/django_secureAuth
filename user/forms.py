from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm

from django import forms 
from django.contrib.auth.forms import AuthenticationForm
from django.forms.widgets import PasswordInput,TextInput

from .models import Member

class CreateUserForm(UserCreationForm):

    class Meta :
        model = Member
        fields = ['username','email','password1','password2']

    def clean(self):
        cleaned_data = super().clean()  # Call the parent class's clean method
        password1 = cleaned_data.get("password1")  
        password2 = cleaned_data.get("password2")  

        if password1 and password2 and password1 != password2:  # Check if passwords match
            raise forms.ValidationError("Passwords do not match") 
        

class UpdateUserForm(forms.ModelForm):
    class Meta :
        model = Member
        fields = ['username','email','image', 'title', 'skills', 'major',]


class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=TextInput())
    password = forms.CharField(widget=PasswordInput())


class OTPForm(forms.Form):
    otp = forms.CharField(label="Enter OTP", max_length=6, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Enter OTP'
    }))    


