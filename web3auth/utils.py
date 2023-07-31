from web3 import Account
from eth_utils import is_hex_address, to_checksum_address
from eth_hash.auto import keccak
from django import forms


def sig_to_vrs(sig):
    r = int(sig[2:66], 16)
    s = int(sig[66:130], 16)
    v = int(sig[130:], 16)
    return v, r, s


def hash_personal_message(msg):
    padded = "\x19Ethereum Signed Message:\n" + str(len(msg)) + msg
    return keccak(bytes(padded, 'utf8'))


def recover_to_addr(msg, sig):
    msghash = hash_personal_message(msg)
    vrs = sig_to_vrs(sig)
    pubkey = Account.recover(msghash, signature=(vrs[1], vrs[2], vrs[0]))
    return to_checksum_address(pubkey)


def validate_eth_address(value):
    if not is_hex_address(value):
        raise forms.ValidationError(
            '%s is not a valid Ethereum address' % value,
            params={'value': value},
        )
