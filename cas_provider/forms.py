from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate

from models import ServiceTicket, LoginTicket
from utils import create_login_ticket


class LoginForm(forms.Form):
    email = forms.CharField(max_length=255)
    password = forms.CharField(widget=forms.PasswordInput)
    #warn = forms.BooleanField(required=False)  # TODO: Implement
    lt = forms.CharField(widget=forms.HiddenInput, initial=create_login_ticket, required=False)
    service = forms.CharField(widget=forms.HiddenInput, required=False)
    remember_me = forms.BooleanField(required=False)

    def __init__(self, *args, **kwargs):
        # renew = kwargs.pop('renew', None)
        # gateway = kwargs.pop('gateway', None)
        request = kwargs.pop('request', None)
        super(LoginForm, self).__init__(*args, **kwargs)
        self.request = request

    def clean_remember_me(self):
        remember = self.cleaned_data['remember_me']
        if not remember and self.request is not None:
            self.request.session.set_expiry(0)

    def clean_lt(self):
        lt = self.cleaned_data.get('lt',
                                   self.initial.get('lt', None))
        if lt is None:
            lt = self.fields['lt'].initial()
        try:
            login_ticket = LoginTicket.objects.get(ticket=lt)
        except LoginTicket.DoesNotExist:
            raise forms.ValidationError("Login ticket expired. Please try again.")
        else:
            login_ticket.delete()
            

class MergeLoginForm(LoginForm):
    email = forms.CharField(max_length=255, widget=forms.HiddenInput)
