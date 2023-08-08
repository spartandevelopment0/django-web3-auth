from eth_utils import is_hex_address, to_checksum_address
from eth_account import Account
from eth_account.messages import defunct_hash_message
from django import forms


def sig_to_vrs(sig):
    r = int(sig[2:66], 16)
    s = int(sig[66:130], 16)
    v = int(sig[130:], 16)
    return v, r, s


def hash_personal_message(msg):
    message_hash = defunct_hash_message(text=msg)
    return message_hash


def recover_to_addr(msg, sig):
    msghash = hash_personal_message(msg)
    vrs = sig_to_vrs(sig)
    signature = '0x' + ''.join([f'{part:02x}' for part in (vrs[1], vrs[2], vrs[0])])
    address = Account._recover_hash(msghash, signature=signature)
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
