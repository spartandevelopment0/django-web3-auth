from rest_framework import serializers
from web3auth.dj_rest_auth.serializers import LoginSerializer

from .utils import validate_eth_address
from .backend import Web3Backend

class Web3SignupLoginSerializer(LoginSerializer):
    signature = serializers.CharField(max_length=132)
    address = serializers.CharField(max_length=42, validators=[validate_eth_address])
    
    def get_fields(self):
        fields = super().get_fields()
        del fields['password']
        return fields

    def validate(self, attrs):
        # Instantiate Web3Backend and authenticate
        web3_auth_backend = Web3Backend()
        self.user = web3_auth_backend.authenticate(
            request=self.context.get('request'),
            address=attrs['address'],
            token=self.context.get('request').session.get('login_token'),
            signature=attrs['signature']
        )

        if self.user is None:
            raise serializers.ValidationError('Authentication with provided address and signature failed.')
        
        # We assume that if a user isn't active, they can't log in
        if not self.user.is_active:
            raise serializers.ValidationError('This user is not active.')

        return attrs
