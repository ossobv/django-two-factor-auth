from binascii import unhexlify
from json import dumps, loads
from time import time

from django import forms
from django.forms import Form, ModelForm
from django.utils.translation import ugettext_lazy as _
from django_otp.forms import OTPAuthenticationFormMixin
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import (
    PhoneDevice, get_available_methods, get_available_phone_methods,
)
from .utils import totp_digits
from .validators import validate_international_phonenumber

try:
    from otp_yubikey.models import RemoteYubikeyDevice, YubikeyDevice
except ImportError:
    RemoteYubikeyDevice = YubikeyDevice = None
try:
    from django_otp_u2f.models import U2fDevice
except ImportError:
    U2fDevice = None


class MethodForm(forms.Form):
    method = forms.ChoiceField(label=_("Method"),
                               initial='generator',
                               widget=forms.RadioSelect)

    def __init__(self, **kwargs):
        super(MethodForm, self).__init__(**kwargs)
        self.fields['method'].choices = get_available_methods()


class PhoneNumberMethodForm(ModelForm):
    number = forms.CharField(label=_("Phone Number"),
                             validators=[validate_international_phonenumber])
    method = forms.ChoiceField(widget=forms.RadioSelect, label=_('Method'))

    class Meta:
        model = PhoneDevice
        fields = 'number', 'method',

    def __init__(self, **kwargs):
        super(PhoneNumberMethodForm, self).__init__(**kwargs)
        self.fields['method'].choices = get_available_phone_methods()


class PhoneNumberForm(ModelForm):
    # Cannot use PhoneNumberField, as it produces a PhoneNumber object, which cannot be serialized.
    number = forms.CharField(label=_("Phone Number"),
                             validators=[validate_international_phonenumber])

    class Meta:
        model = PhoneDevice
        fields = 'number',


class DeviceValidationForm(forms.Form):
    token = forms.IntegerField(label=_("Token"), min_value=1, max_value=int('9' * totp_digits()))

    error_messages = {
        'invalid_token': _('Entered token is not valid.'),
    }

    def __init__(self, device, **args):
        super(DeviceValidationForm, self).__init__(**args)
        self.device = device

    def clean_token(self):
        token = self.cleaned_data['token']
        if not self.device.verify_token(token):
            raise forms.ValidationError(self.error_messages['invalid_token'])
        return token


class YubiKeyDeviceForm(DeviceValidationForm):
    token = forms.CharField(label=_("YubiKey"), widget=forms.PasswordInput())

    error_messages = {
        'invalid_token': _("The YubiKey could not be verified."),
    }

    def clean_token(self):
        self.device.public_id = self.cleaned_data['token'][:-32]
        return super(YubiKeyDeviceForm, self).clean_token()


class U2fDeviceForm(forms.Form):
    session_key = 'django_two_factor-u2f-challenge'

    token = forms.CharField(
        label=_('U2F'), widget=forms.HiddenInput())

    class Media:
        js = ('two_factor/js/u2f-api.js',)

    error_messages = {
        'invalid_token': _("The U2F key could not be verified."),
    }

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super(U2fDeviceForm, self).__init__(*args, **kwargs)
        if not self.is_bound:
            self.challenge = U2fDevice.begin_registration(
                self.request.user, self.request.build_absolute_uri('/')[:-1])
            self.request.session[self.session_key] = self.challenge
        else:
            self.challenge = self.request.session.get(self.session_key)

    @property
    def data_for_client(self):
        return dumps(self.challenge)

    def clean(self):
        try:
            self.device = U2fDevice.complete_registration(
                self.request.user, self.challenge,
                loads(self.cleaned_data['token']), name='default')
            self.cleaned_data['persistent_id'] = self.device.persistent_id
        except Exception:
            raise forms.ValidationError(self.error_messages['invalid_token'])
        finally:
            if self.session_key in self.request.session:
                del self.request.session[self.session_key]
        return self.cleaned_data


class TOTPDeviceForm(forms.Form):
    token = forms.IntegerField(label=_("Token"), min_value=0, max_value=int('9' * totp_digits()))

    error_messages = {
        'invalid_token': _('Entered token is not valid.'),
    }

    def __init__(self, key, user, metadata=None, **kwargs):
        super(TOTPDeviceForm, self).__init__(**kwargs)
        self.key = key
        self.tolerance = 1
        self.t0 = 0
        self.step = 30
        self.drift = 0
        self.digits = totp_digits()
        self.user = user
        self.metadata = metadata or {}

    @property
    def bin_key(self):
        """
        The secret key as a binary string.
        """
        return unhexlify(self.key.encode())

    def clean_token(self):
        token = self.cleaned_data.get('token')
        validated = False
        t0s = [self.t0]
        key = self.bin_key
        if 'valid_t0' in self.metadata:
            t0s.append(int(time()) - self.metadata['valid_t0'])
        for t0 in t0s:
            for offset in range(-self.tolerance, self.tolerance):
                if totp(key, self.step, t0, self.digits, self.drift + offset) == token:
                    self.drift = offset
                    self.metadata['valid_t0'] = int(time()) - t0
                    validated = True
        if not validated:
            raise forms.ValidationError(self.error_messages['invalid_token'])
        return token

    def save(self):
        return TOTPDevice.objects.create(user=self.user, key=self.key,
                                         tolerance=self.tolerance, t0=self.t0,
                                         step=self.step, drift=self.drift,
                                         digits=self.digits,
                                         name='default')


class DisableForm(forms.Form):
    understand = forms.BooleanField(label=_("Yes, I am sure"))


class AuthenticationTokenForm(OTPAuthenticationFormMixin, Form):
    session_key = 'django_two_factor-u2f-challenge'
    otp_token = forms.IntegerField(label=_("Token"), min_value=1,
                                   max_value=int('9' * totp_digits()))

    otp_token.widget.attrs.update({'autofocus': 'autofocus'})

    # Our authentication form has an additional submit button to go to the
    # backup token form. When the `required` attribute is set on an input
    # field, that button cannot be used on browsers that implement html5
    # validation. For now we'll use this workaround, but an even nicer
    # solution would be to move the button outside the `<form>` and into
    # its own `<form>`.
    use_required_attribute = False

    def __init__(self, request, user, initial_device, **kwargs):
        """
        `initial_device` is either the user's default device, or the backup
        device when the user chooses to enter a backup token. The token will
        be verified against all devices, it is not limited to the given
        device.
        """
        super(AuthenticationTokenForm, self).__init__(**kwargs)
        self.challenge = None
        self.request = request
        self.user = user
        self.initial_device = initial_device

        # YubiKey generates a OTP of 44 characters (not digits). So if the
        # user's primary device is a YubiKey, replace the otp_token
        # IntegerField with a CharField.
        if RemoteYubikeyDevice and YubikeyDevice and \
                isinstance(
                    initial_device, (RemoteYubikeyDevice, YubikeyDevice)):
            self.fields['otp_token'] = forms.CharField(
                label=_('YubiKey'), widget=forms.PasswordInput())

        if U2fDevice and isinstance(initial_device, U2fDevice):
            self.fields['otp_token'] = forms.CharField(
                label=_('U2F'), widget=forms.HiddenInput())

            if not self.is_bound:
                self.challenge = U2fDevice.begin_authentication(
                    self.user,
                    self.request.build_absolute_uri('/')[:-1])
                self.request.session[self.session_key] = self.challenge
            else:
                self.challenge = self.request.session.get(self.session_key)

    @property
    def data_for_client(self):
        return dumps(self.challenge)

    def _chosen_device(self, user):
        if self.challenge is not None:
            self.initial_device.create_verify_token(self.challenge)
        return self.initial_device

    def clean(self):
        try:
            self.clean_otp(self.user)
        finally:
            if self.session_key in self.request.session:
                del self.request.session[self.session_key]
        return self.cleaned_data

    class Media:
        js = ('two_factor/js/u2f-api.js',)


class BackupTokenForm(AuthenticationTokenForm):
    otp_token = forms.CharField(label=_("Token"))
