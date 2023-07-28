# import string

# from django import forms
# from django.contrib.auth import get_user_model

# from web3auth.settings import app_settings
# from .utils import validate_eth_address


# class LoginForm(forms.Form):
#     signature = forms.CharField(widget=forms.HiddenInput, max_length=132)
#     address = forms.CharField(widget=forms.HiddenInput, max_length=42, validators=[validate_eth_address])

#     def __init__(self, token, *args, **kwargs):
#         self.token = token
#         super(LoginForm, self).__init__(*args, **kwargs)

#     def clean_signature(self):
#         sig = self.cleaned_data['signature']
#         if any([
#             len(sig) != 132,
#             sig[130:] != '1b' and sig[130:] != '1c',
#             not all(c in string.hexdigits for c in sig[2:])
#         ]):
#             raise forms.ValidationError('Invalid signature')
#         return sig


# # list(set()) here is to eliminate the possibility of double including the address field
# signup_fields = list(set(app_settings.WEB3AUTH_USER_SIGNUP_FIELDS + [app_settings.WEB3AUTH_USER_ADDRESS_FIELD]))


# class SignupForm(forms.ModelForm):

#     def __init__(self, *args, **kwargs):
#         # first call parent's constructor
#         super().__init__(*args, **kwargs)

#         self.fields[app_settings.WEB3AUTH_USER_ADDRESS_FIELD].required = True
#         self.fields["address"].widget.attrs.update({'class': 'form-control form-control-lg m-2', 'title': 'Your ethereum address, which you can easily use for signing messages.'})
#         self.fields["username"].widget.attrs.update({'class': 'form-control form-control-lg m-2', 'title': 'Username to be displayed'})


#     def clean_address_field(self):
#         validate_eth_address(self.cleaned_data[app_settings.WEB3AUTH_USER_ADDRESS_FIELD])
#         return self.cleaned_data[app_settings.WEB3AUTH_USER_ADDRESS_FIELD].lower()

#     class Meta:
#         model = get_user_model()
#         fields = signup_fields


# # hack to set the method for cleaning address field
# setattr(SignupForm, 'clean_' + app_settings.WEB3AUTH_USER_ADDRESS_FIELD, SignupForm.clean_address_field)
