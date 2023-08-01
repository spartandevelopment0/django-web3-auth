from abc import abstractmethod, ABC
from typing import Optional

from django.contrib.auth import get_user_model, backends
from django.conf import settings

from web3auth.utils import recover_to_addr

User = get_user_model()

DEFAULT_ADDRESS_FIELD = 'username'
ADDRESS_FIELD = getattr(
    settings, 'WEB3AUTH_USER_ADDRESS_FIELD', DEFAULT_ADDRESS_FIELD)

class Web3Backend(backends.ModelBackend):

    def authenticate(
            self,
            request,
            wallet_address,
            token,
            signature
    ) -> Optional[User]:
        # check if the address the user has provided matches the signature
        if wallet_address != recover_to_addr(token, signature):
            raise ValueError('Wallet address does not match signature')
        else:
            # get address field for the user model
            kwargs = {
                f"{ADDRESS_FIELD}__iexact": wallet_address
            }
            # try to get user with provided data
            user = User.objects.filter(**kwargs).first()
            if user is None:
                # create the user if it does not exist
                return self.create_user(wallet_address)
            return user

    def create_user(self, wallet_address):
        user = self._gen_user(wallet_address)
        fields = [field.name for field in User._meta.fields]
        if (
                ADDRESS_FIELD != DEFAULT_ADDRESS_FIELD
                and 'username' in fields
        ):
            user.username = user.generate_username()
        user.save()
        return user

    def _gen_user(self, wallet_address: str) -> User:
        return User(**{ADDRESS_FIELD: wallet_address, 'is_active': True, 'wallet_address': wallet_address})
