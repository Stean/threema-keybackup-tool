#!/usr/bin/env python
"""
Author: Stean
Description:
This script is based on Threema's official whitepaper (https://threema.ch/press-files/cryptography_whitepaper.pdf) and allows to check, whether a given backup key + password is correct and is able to extract the encoded information.
"""

import base64
import hashlib
import logging
import salsa20
import binascii

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def decode_backup_code(dashed_input):
    """
    Input: Threema private key in the dashed form, consisting of 80 characters (A-Z, 2-7), which are grouped into groups of four characters, which are separated with dashes
    Example: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    """
    encrypted_encoded_keyinput = dashed_input.replace("-","")
    logger.debug("[decode_backup_code] encrypted_encoded_keyinput (without dashes): %s", encrypted_encoded_keyinput)

    encrypted_keyinput = base64.b32decode(encrypted_encoded_keyinput)
    return encrypted_keyinput

def derive_key_decryption_key(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password, salt, 100000, dklen=32)


def decrypt_key(encrypted_keyinput, password):
    """
    Uses the output of the decode_backup_code function as input, extracts the salt, derives the key_decryption_key using the salt and the user-provided password and finally decrypts the private key (incl. all other encoded information)
    """
    salt = encrypted_keyinput[:8]
    ciphertext = encrypted_keyinput[8:]

    key_decryption_key = derive_key_decryption_key(password, salt)
    logger.info("[decrypt_key] derived key_decryption_key: %s", repr(key_decryption_key))

    decrypted_keyinfo = salsa20.XSalsa20_xor(ciphertext, "\x00"*24, key_decryption_key)

    return decrypted_keyinfo

def parse_keyinfo(decrypted_keyinfo):
    assert len(decrypted_keyinfo)==42, "decrypted_keyinfo has invalid length of " + len(decrypted_keyinfo) + " instead of 42"

    result = dict()

    result["identity"]    = decrypted_keyinfo[:8]     # 8 character Threema ID
    result["private_key"] = decrypted_keyinfo[8:8+32] # 32 byte private key
    result["verification_bytes"] = decrypted_keyinfo[-2:] # the first two bytes of the resulting hash are used during restoration to verify with reasonable con dence that the provided password was correct

    return result

def verify_keyinfo(keyinfo_dict):
    # Calc hash
    h = hashlib.sha256()
    h.update(keyinfo_dict["identity"])      # Feed in ID
    h.update(keyinfo_dict["private_key"])   # Feed in private Key
    logger.debug("SHA256(identity + private_key): %s", h.hexdigest())

    return h.digest()[:2] == keyinfo_dict["verification_bytes"]

def print_keyinfo_dict(keyinfo_dict):
    print("============ Result ============")
    print("identity: %s" % keyinfo_dict["identity"])
    print("private key (bin): %s" % repr(keyinfo_dict["private_key"]))
    print("private key (hex): %s" % binascii.hexlify(keyinfo_dict["private_key"]))
    print("verification hash bytes: %s" % repr(keyinfo_dict["verification_bytes"]))

##### Main
backup_key = "<insert your backup key here>"
backup_key_password = "<insert your backup password here>"

encrypted_keyinput = decode_backup_code(backup_key)
logger.info("decoded backup code: %s", repr(encrypted_keyinput))

decrypted_keyinfo = decrypt_key(encrypted_keyinput, backup_key_password)
logger.info("decrypted keyinfo: %s", repr(decrypted_keyinfo))

keyinfo_dict = parse_keyinfo(decrypted_keyinfo)

if verify_keyinfo(keyinfo_dict):
    print "Valid: TRUE"
    print_keyinfo_dict(keyinfo_dict)
else:
    print "Valid: FALSE"
