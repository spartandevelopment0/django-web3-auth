import random
import string

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.forms import ValidationError
from django.utils import timezone
from django.contrib.auth import authenticate


from web3auth.dj_rest_auth.views import LoginView
from web3auth.dj_rest_auth.models import get_token_model
from web3auth.dj_rest_auth.utils import jwt_encode
from .app_settings import api_settings
from .serializers import Web3SignupLoginSerializer



class Web3SignupLoginView(LoginView):
    serializer_class = Web3SignupLoginSerializer
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        login_token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
        request.session['login_token'] = login_token
        return Response({'data': login_token, 'success': True})

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        self.web3_login()
        return self.get_web3_response()
    
    def get_response_serializer(self):
        if api_settings.USE_JWT:

            if api_settings.JWT_AUTH_RETURN_EXPIRATION:
                response_serializer = api_settings.JWT_SERIALIZER_WITH_EXPIRATION
            else:
                response_serializer = api_settings.JWT_SERIALIZER

        else:
            response_serializer = api_settings.TOKEN_SERIALIZER
        return response_serializer


    def web3_login(self):
        wallet_address = self.serializer.validated_data.get("wallet_address")
        signature = self.serializer.validated_data.get("signature")
        token = self.request.session.get('login_token')
        
        if not token:
            raise ValidationError("No login token in session, please request token again by sending GET request to this url")

        user = authenticate(request=self.request, token=token, wallet_address=wallet_address, signature=signature)

        if user is None:
            raise ValidationError('Authentication with provided address and signature failed.')

        if not user.is_active:
            raise ValidationError('This user is not active.')

        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        del self.request.session['login_token']

        self.user = user

        token_model = get_token_model()

        if api_settings.USE_JWT:
            self.access_token, self.refresh_token = jwt_encode(self.user)
        elif token_model:
            self.token = api_settings.TOKEN_CREATOR(token_model, self.user, self.serializer)

        if api_settings.SESSION_LOGIN:
            self.process_login()

    def get_web3_response(self):
        serializer_class = self.get_response_serializer()

        if api_settings.USE_JWT:
            from rest_framework_simplejwt.settings import (
                api_settings as jwt_settings,
            )
            access_token_expiration = (timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME)
            refresh_token_expiration = (timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME)
            return_expiration_times = api_settings.JWT_AUTH_RETURN_EXPIRATION
            auth_httponly = api_settings.JWT_AUTH_HTTPONLY

            data = {
                'user': self.user,
                'access': self.access_token,
            }

            if not auth_httponly:
                data['refresh'] = self.refresh_token
            else:
                data['refresh'] = ""

            if return_expiration_times:
                data['access_expiration'] = access_token_expiration
                data['refresh_expiration'] = refresh_token_expiration

            serializer = serializer_class(
                instance=data,
                context=self.get_serializer_context(),
            )
        elif self.token:
            serializer = serializer_class(
                instance=self.token,
                context=self.get_serializer_context(),
            )
        else:
            return Response(status=status.HTTP_204_NO_CONTENT)

        response = Response(serializer.data, status=status.HTTP_200_OK)
        if api_settings.USE_JWT:
            from web3auth.dj_rest_auth.jwt_auth import set_jwt_cookies
            set_jwt_cookies(response, self.access_token, self.refresh_token)
        return response
