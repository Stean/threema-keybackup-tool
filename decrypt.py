#!/usr/bin/env python
import base64
import Crypto.Hash.SHA256
import logging
from Crypto.Cipher import Salsa20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

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
    return PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=Crypto.Hash.SHA256)


def decrypt_key(encrypted_keyinput, password):
    """
    Uses the output of the decode_backup_code function as input, extracts the salt, derives the key_decryption_key using the salt and the user-provided password and finally decrypts the private key (incl. all other encoded information)
    """
    salt = encrypted_keyinput[:8]
    ciphertext = encrypted_keyinput[8:]

    key_decryption_key = derive_key_decryption_key(password, salt)
    logger.info("[decrypt_key] derived key_decryption_key: %s", repr(key_decryption_key))

    cipher = Salsa20.new(key=key_decryption_key, nonce="\x00"*8)
    decrypted_keyinfo = cipher.decrypt(ciphertext)

    return decrypted_keyinfo

def verify_keyinfo(decrypted_keyinfo):
    logger.debug("[verify_keyinfo] len(decrypted_keyinfo): %d", len(decrypted_keyinfo))
    assert len(decrypted_keyinfo)==42, "decrypted_keyinfo has invalid length of " + len(decrypted_keyinfo) + " instead of 42"

    identity    = decrypted_keyinfo[:8]     # 8 character Threema ID
    private_key = decrypted_keyinfo[8:8+32] # 32 byte private key
    verification_hash_bytes = decrypted_keyinfo[-2:] # the first two bytes of the resulting hash are used during restoration to verify with reasonable con dence that the provided password was correct

    logger.info("identity: %s", repr(identity))
    logger.info("private_key: %s", repr(private_key))
    logger.info("verification_hash_bytes: %s", repr(verification_hash_bytes))

    # Calc hash
    h = SHA256.new()
    h.update(identity + private_key)
    logger.debug("SHA256(identity + private_key): %s", h.hexdigest())

    return h.digest()[:2] == verification_hash_bytes


##### Main
backup_key = "XXX"
backup_key_password = "12345678"

encrypted_keyinput = decode_backup_code(backup_key)
logger.info("decoded backup code: %s", repr(encrypted_keyinput))

decrypted_keyinfo = decrypt_key(encrypted_keyinput, backup_key_password)

logger.info("decrypted keyinfo: %s", repr(decrypted_keyinfo))

verification_result = verify_keyinfo(decrypted_keyinfo)
if verification_result:
    print "Valid: TRUE"
else:
    print "Valid: FALSE"
