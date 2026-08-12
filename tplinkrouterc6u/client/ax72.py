"""
TP-Link router client for the Archer AX72 and possibly other AX-series
devices sharing its firmware's login-signature scheme.

The standard AX-series client (`TplinkRouter`, in `c6u.py`) signs login
requests with MD5 + flat 53-byte PKCS1v1.5-chunked RSA, via the shared
`EncryptionWrapper.get_signature()`.
The AX72's firmware instead expects:
  1. SHA256 hash of username+password instead of MD5
  2. RSA-OAEP (not PKCS1v1.5) padding for the login signature
  3. No trailing '&confirm=true' in the login body
Sending the standard scheme gets a 403 on every login attempt.

Password encryption itself is unaffected: it still uses PKCS1v1.5 against
the separate password RSA key (`pwdNN`/`pwdEE`), inherited unchanged via
`TplinkEncryption.rsa_encrypt()`.
Only the login *signature* differs, which is why this class only overrides
`_get_login_data()`, `_prepare_data()`, and `supports()`. `authorize()`
itself, its 403-retry logic, and every read endpoint
(`get_firmware`/`get_status`/`get_ipv4_status`/etc.) are inherited unchanged
from `TplinkRouter`/`TplinkBaseRouter`.

This class's signature chunking is intentionally *not* a straight port of
`TplinkRouterSG`'s (see #185). SG's fix chunks the signature string directly
into OAEP-sized pieces. The AX72 firmware, as confirmed by capturing and
replaying a real login (see `test_client_ax72.py`'s regression test and this
project's own history), instead expects *nested* chunking: the string is split
into 53-byte outer pieces first (matching the legacy PKCS1v1.5 layout), and
each outer piece is then further split into OAEP-safe inner pieces before
RSA-OAEP-encrypting each independently. These produce different block
boundaries past the first 53 bytes, and only the nested form has been
confirmed against a real device. Simplifying to SG's flatter scheme here would
be an unverified behavioral change, not just a style choice.

Confirmed end-to-end (login, get_ipv4_status, get_status, get_firmware, logout) against a real Archer AX72.
"""

from hashlib import sha256

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import construct
from binascii import hexlify

from tplinkrouterc6u.client.c6u import TplinkRouter

# Sized for PKCS1v1.5's 11-byte overhead, matching
# EncryptionWrapper.get_signature's legacy chunking. This is only an upper
# bound: the AX72's 512-bit auth key gives an OAEP capacity of 22 bytes, so
# the min() below always picks the OAEP-safe size in practice. The cap exists
# so behavior would not silently change if this class were ever reused against
# a larger-keyed device.
SIGNATURE_OFFSET = 53
# SHA-1 (20 bytes): pycryptodome's PKCS1_OAEP.new() default hash, giving OAEP
# overhead of 2*20+2 = 42 bytes.
OAEP_HASH_LEN = 20


class TplinkRouterAX72(TplinkRouter):
    """
    Client for the Archer AX72 and any AX-series device presenting the same
    512-bit auth key size, which the standard PKCS1v1.5-based signing cannot
    authenticate against.
    """

    def supports(self) -> bool:
        """Cheap pre-filter before attempting a real login.

        Mirrors `TplinkRouterV1_11`'s approach.

        The auth key TP-Link's /login?form=auth serves is 512-bit
        (128 hex chars) on the AX72;
        every standard-scheme AX-series device this project has seen serves a larger key.
        Key size alone does not prove which signing scheme a device expects:
        a 512-bit key is also compatible with PKCS1v1.5, but a real
        authorize()+logout() attempt right after settles that,
        and get_client()'s caller falls through to the next provider if this one raises,
        so a false-positive pre-filter match costs one extra failed login, not a wrong classification.
        """
        if len(self.password) > 125:
            return False

        try:
            self._request_pwd()
            self._request_seq()
            if len(self.nn) != 128:
                return False
            self.authorize()
            self.logout()
            return True
        except Exception:
            pass

        return False

    @staticmethod
    def _get_login_data(crypted_pwd: str) -> str:
        return 'operation=login&password={}'.format(crypted_pwd)

    @staticmethod
    def _rsa_oaep_encrypt(data: bytes, nn: str, ee: str) -> str:
        key = construct((int(nn, 16), int(ee, 16)))
        result = hexlify(PKCS1_OAEP.new(key).encrypt(data)).decode()
        key_len = len(nn)
        return result.zfill(key_len) if len(result) < key_len else result

    def _build_login_signature(self, seq_and_len: int, hash_value: str) -> str:
        """Build the AX72's nested RSA-OAEP login signature.

        See the module docstring for why this differs from
        `TplinkRouterSG`'s flat chunking.
        """
        sign_str = '{}&h={}&s={}'.format(self._encryption._get_aes_string(), hash_value, seq_and_len)

        modulus_bytes = len(self.nn) // 2
        inner_step = min(SIGNATURE_OFFSET, modulus_bytes - 2 * OAEP_HASH_LEN - 2)

        sign = ''
        for outer_start in range(0, len(sign_str), SIGNATURE_OFFSET):
            outer_piece = sign_str[outer_start:outer_start + SIGNATURE_OFFSET].encode()
            for inner_start in range(0, len(outer_piece), inner_step):
                chunk = outer_piece[inner_start:inner_start + inner_step]
                sign += self._rsa_oaep_encrypt(chunk, self.nn, self.ee)

        return sign

    def _prepare_data(self, data: str) -> dict:
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)
        hash_value = sha256((self.username + self.password).encode()).hexdigest()

        sign = self._build_login_signature(int(self._seq) + data_len, hash_value)

        return {'sign': sign, 'data': encrypted_data}
