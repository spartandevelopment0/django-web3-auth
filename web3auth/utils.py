from eth_utils import is_hex_address, to_checksum_address
from eth_account import Account
from eth_account.messages import encode_defunct
from django import forms

def recover_to_addr(message, signature):
    internal_message = encode_defunct(text=message)
    address = Account.recover_message(internal_message, signature=signature) #._recover_hash(msghash, signature=signature)
    return to_checksum_address(address)


def validate_eth_address(value):
    if not is_hex_address(value):
        raise forms.ValidationError(
            '%s is not a valid Ethereum address' % value,
            params={'value': value},
        )


def check_zero_address(value):
    if value == "0x0000000000000000000000000000000000000000":
        raise forms.ValidationError(
            'The zero Ethereum address is not allowed',
            params={'value': value},
        )
