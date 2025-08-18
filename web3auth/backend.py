import logging
from typing import Optional

from django.conf import settings
from django.contrib.auth import get_user_model, backends
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from web3auth.utils import recover_to_addr

User = get_user_model()
LOGGER = logging.getLogger(__name__)

DEFAULT_ADDRESS_FIELD = "username"
ADDRESS_FIELD = getattr(settings, "WEB3AUTH_USER_ADDRESS_FIELD", DEFAULT_ADDRESS_FIELD)


class Web3Backend(backends.ModelBackend):

    def authenticate(self, request, wallet_address, token, signature) -> Optional[User]:
        # check if the address the user has provided matches the signature
        try:
            if wallet_address != recover_to_addr(token, signature):
                msg = _("Invalid signature")
                raise exceptions.ValidationError(msg)
            else:
                # get address field for the user model
                kwargs = {f"{ADDRESS_FIELD}__iexact": wallet_address}
                # try to get user with provided data
                user = User.objects.filter(**kwargs).first()
                if user is None:
                    # create the user if it does not exist
                    ip_address = get_request_ip(request)
                    if not ip_address:
                        LOGGER.warning(
                            "Couldn't get IP address while creating user for wallet: %s",
                            wallet_address,
                        )
                    return self.create_user(wallet_address, ip_address=ip_address)
                return user
        except Exception:
            msg = _("Invalid signature")
            raise exceptions.ValidationError(msg)

    def create_user(self, wallet_address, **extra):
        user = self._gen_user(wallet_address, **extra)
        fields = [field.name for field in User._meta.fields]
        if ADDRESS_FIELD != DEFAULT_ADDRESS_FIELD and "username" in fields:
            user.username = user.generate_username()
        user.save()
        return user

    def _gen_user(self, wallet_address: str, **extra) -> User:
        return User(
            **{
                ADDRESS_FIELD: wallet_address,
            },
            is_active=True,
            wallet_address=wallet_address,
            **extra,
        )


def get_request_ip(request):
    if x_forwarded_for := request.META.get("HTTP_X_FORWARDED_FOR"):
        return x_forwarded_for.split(",")[0]

    return request.META.get("REMOTE_ADDR")
