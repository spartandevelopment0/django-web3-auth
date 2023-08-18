from rest_framework import serializers, exceptions
from django.core.cache import cache
from web3auth.dj_rest_auth.serializers import LoginSerializer
from .app_settings import api_settings
from .utils import validate_eth_address, check_zero_address
from .backend import Web3Backend
from django.utils.translation import gettext_lazy as _

class Web3SignupLoginRequestSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=42, required=True, validators=[validate_eth_address, check_zero_address])

class Web3SignupLoginResponseSerializer(serializers.Serializer):
    data = serializers.CharField(max_length=32)

class Web3SignupLoginSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=42, required=True, validators=[validate_eth_address, check_zero_address])    
    signature = serializers.CharField(max_length=132, required=True)

    @staticmethod
    def validate_auth_user_status(user):
        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)
        
    def validate(self, attrs):
        wallet_address = attrs.get('wallet_address')
        signature = attrs.get('signature')
        login_token = cache.get(api_settings.CACHE_KEY_PREFIX + wallet_address)
        if not login_token:
            msg = _('Login token has expired.')
            raise exceptions.ValidationError(msg)

        # Instantiate Web3Backend and authenticate
        web3_auth_backend = Web3Backend()
        user = web3_auth_backend.authenticate(
            request=self.context.get('request'),
            wallet_address=wallet_address,
            token=login_token,
            signature=signature
        )

        if not user:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)
        
        # Did we get back an active user?
        self.validate_auth_user_status(user)

        attrs['user'] = user
        return attrs
