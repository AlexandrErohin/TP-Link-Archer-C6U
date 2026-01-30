"""
TP-Link router client for SG_L1_S2 / CE_RED certified devices.

Routers with these certifications (e.g., Archer BE3600, Wi-Fi 7 models)
use an enhanced encryption scheme:
  1. SHA256 hash instead of MD5 for authentication
  2. PKCS1-OAEP RSA padding for login signature encryption
  3. HMAC-SHA256 for non-login request signatures
  4. Dynamic hash replacement: SHA256(encrypted_data) per request

Fixes: https://github.com/AlexandrErohin/home-assistant-tplink-router/issues/220
"""

import hmac
import hashlib
import json
from re import search
from hashlib import sha256
from base64 import b64encode, b64decode
from random import randint
from logging import Logger
from urllib.parse import quote

from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5, AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify
from requests import post

from tplinkrouterc6u.client.c6u import TplinkBaseRouter
from tplinkrouterc6u.common.exception import ClientException, ClientError

# SG_L1_S2 and CE_RED certifications that trigger enhanced encryption
SG_CERTIFICATIONS = ['SG CLS L1 STAGE2', 'EU CE RED']

SIGNATURE_OFFSET = 53
AES_KEY_LEN = 16


class TplinkRouterSG(TplinkBaseRouter):
    """
    Client for TP-Link routers with SG_L1_S2 / CE_RED certification.

    These routers use SHA256 + OAEP + HMAC-SHA256 instead of the standard
    MD5 + PKCS1_v1_5 + RSA encryption scheme.
    """

    def __init__(self, host: str, password: str, username: str = 'admin',
                 logger: Logger = None, verify_ssl: bool = True,
                 timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._aes_key = ''
        self._aes_iv = ''
        self._hash = ''
        self._seq = 0
        self._nn = ''
        self._ee = ''
        self._pwdNN = ''
        self._pwdEE = ''
        self._data_block = 'data'

    def supports(self) -> bool:
        """Check if this router uses SG/CE_RED encryption."""
        if len(self.password) > 125:
            return False
        try:
            if not self._check_sg_certification():
                return False
            self._request_pwd_keys()
            self.authorize()
            self.logout()
            return True
        except Exception:
            return False

    def _check_sg_certification(self) -> bool:
        """Check if the router has SG_L1_S2 or CE_RED certification."""
        url = '{}/cgi-bin/luci/;stok=/device_config?form=config'.format(self.host)
        response = post(
            url, data='operation=read',
            headers=self._headers_login,
            timeout=self.timeout, verify=self._verify_ssl,
        )
        try:
            data = response.json()
            certs = data.get('data', {}).get('certification', [])
            return any(c in SG_CERTIFICATIONS for c in certs)
        except Exception:
            return False

    def _generate_aes_key(self) -> None:
        """Generate random AES key and IV (16 random digits, matching JS behavior)."""
        self._aes_key = ''.join([str(randint(0, 9)) for _ in range(AES_KEY_LEN)])
        self._aes_iv = ''.join([str(randint(0, 9)) for _ in range(AES_KEY_LEN)])

    def _aes_encrypt(self, data: str) -> str:
        """AES-CBC encrypt with PKCS7 padding."""
        cipher = AES.new(self._aes_key.encode(), AES.MODE_CBC, self._aes_iv.encode())
        return b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

    def _aes_decrypt(self, data: str) -> str:
        """AES-CBC decrypt with PKCS7 unpadding."""
        cipher = AES.new(self._aes_key.encode(), AES.MODE_CBC, self._aes_iv.encode())
        return unpad(cipher.decrypt(b64decode(data)), AES.block_size).decode()

    @staticmethod
    def _rsa_v15_encrypt(data: str, n_hex: str, e_hex: str) -> str:
        """RSA encrypt with PKCS1 v1.5 padding (used for password encryption)."""
        key = construct((int(n_hex, 16), int(e_hex, 16)))
        cipher = PKCS1_v1_5.new(key)
        result = hexlify(cipher.encrypt(data.encode())).decode()
        key_len = len(n_hex)
        return result.zfill(key_len) if len(result) < key_len else result

    @staticmethod
    def _rsa_oaep_encrypt(data: str, n_hex: str, e_hex: str) -> str:
        """RSA encrypt with PKCS1-OAEP padding (used for login signature)."""
        key = construct((int(n_hex, 16), int(e_hex, 16)))
        cipher = PKCS1_OAEP.new(key)
        result = hexlify(cipher.encrypt(data.encode())).decode()
        key_len = len(n_hex)
        return result.zfill(key_len) if len(result) < key_len else result

    def _get_aes_formatted_key(self) -> str:
        return 'k={}&i={}'.format(self._aes_key, self._aes_iv)

    def _request_pwd_keys(self) -> None:
        """Get RSA public key for password encryption."""
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)
        response = post(
            url, params={'operation': 'read'},
            timeout=self.timeout, verify=self._verify_ssl,
        )
        try:
            data = response.json()
            self._pwdNN = data['data']['password'][0]
            self._pwdEE = data['data']['password'][1]
        except Exception as e:
            error = ('TplinkRouterSG - Failed to get password keys: {}'.format(e))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _request_auth_keys(self) -> None:
        """Get sequence number and RSA public key for data encryption."""
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)
        response = post(
            url, params={'operation': 'read'},
            timeout=self.timeout, verify=self._verify_ssl,
        )
        try:
            data = response.json()
            self._seq = data['data']['seq']
            self._nn = data['data']['key'][0]
            self._ee = data['data']['key'][1]
        except Exception as e:
            error = ('TplinkRouterSG - Failed to get auth keys: {}'.format(e))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _build_login_signature(self, data_len: int) -> str:
        """Build RSA-OAEP encrypted signature for login requests."""
        sign_str = '{}&h={}&s={}'.format(
            self._get_aes_formatted_key(), self._hash, self._seq + data_len)
        sign = ''
        for i in range(0, len(sign_str), SIGNATURE_OFFSET):
            chunk = sign_str[i:i + SIGNATURE_OFFSET]
            sign += self._rsa_oaep_encrypt(chunk, self._nn, self._ee)
        return sign

    def _build_request_signature(self, data_len: int) -> str:
        """Build HMAC-SHA256 signature for non-login requests."""
        sign_str = 'h={}&s={}'.format(self._hash, self._seq + data_len)
        aes_key = self._get_aes_formatted_key()
        sign = ''
        for i in range(0, len(sign_str), SIGNATURE_OFFSET):
            chunk = sign_str[i:i + SIGNATURE_OFFSET]
            h = hmac.new(aes_key.encode(), chunk.encode(), hashlib.sha256)
            sign += h.hexdigest()
        return sign

    def authorize(self) -> None:
        """Authorize using SHA256 + OAEP encryption scheme."""
        self._request_pwd_keys()
        self._request_auth_keys()

        # SHA256 hash of "admin" + password (not MD5)
        self._hash = sha256(('admin' + self.password).encode()).hexdigest()

        # Generate AES session key
        self._generate_aes_key()

        # RSA encrypt password with PKCS1 v1.5 (password uses v1.5, not OAEP)
        encrypted_pwd = self._rsa_v15_encrypt(self.password, self._pwdNN, self._pwdEE)

        # Build and AES-encrypt the login payload
        login_data = 'operation=login&password={}&confirm=true'.format(encrypted_pwd)
        encrypted_data = self._aes_encrypt(login_data)

        # Build OAEP-encrypted signature
        sign = self._build_login_signature(len(encrypted_data))

        # Send login request
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)
        body = 'sign={}&data={}'.format(sign, quote(encrypted_data))
        response = post(
            url, data=body, headers=self._headers_login,
            timeout=self.timeout, verify=self._verify_ssl,
        )

        try:
            resp = response.json()
            decrypted = json.loads(self._aes_decrypt(resp['data']))

            if not decrypted.get('success'):
                error_data = decrypted.get('data', {})
                raise ClientException(
                    'TplinkRouterSG - Login failed: {}'.format(
                        error_data.get('errorcode', 'unknown')))

            self._stok = decrypted['data']['stok']
            if 'set-cookie' in response.headers:
                regex_result = search(
                    r'sysauth=([^;]+)', response.headers['set-cookie'])
                if regex_result:
                    self._sysauth = regex_result.group(1)
            self._logged = True

        except ClientException:
            raise
        except Exception as e:
            error = ('TplinkRouterSG - Cannot authorize! Error - {}; Response - {}'
                     .format(e, response.text[:200] if response.text else ''))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def request(self, path: str, data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False) -> dict | None:
        """Make an authenticated request using HMAC-SHA256 signatures."""
        if self._logged is False:
            raise Exception('Not authorised')

        # AES encrypt the request data
        encrypted_data = self._aes_encrypt(data)

        # REPLACE_HASH: update hash with SHA256 of encrypted data
        self._hash = sha256(encrypted_data.encode()).hexdigest()

        # Build HMAC-SHA256 signature
        sign = self._build_request_signature(len(encrypted_data))

        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        body = 'sign={}&data={}'.format(sign, quote(encrypted_data))
        response = post(
            url, data=body, headers=self._headers_request,
            cookies={'sysauth': self._sysauth},
            timeout=self.timeout, verify=self._verify_ssl,
        )

        if ignore_response:
            return None

        try:
            resp = response.json()
            decrypted = json.loads(self._aes_decrypt(resp['data']))

            if self._is_valid_response(decrypted):
                return decrypted.get(self._data_block)
            elif ignore_errors:
                return decrypted
        except Exception as e:
            error = ('TplinkRouterSG - Unknown response - {}; Request {} - Response {}'
                     .format(e, path, response.text[:200] if response.text else ''))
            if self._logger:
                self._logger.debug(error)
            raise ClientError(error)

        error = ('TplinkRouterSG - Response with error; Request {} - Response {}'
                 .format(path, response.text[:200] if response.text else ''))
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def _is_valid_response(self, data: dict) -> bool:
        return 'success' in data and data['success'] and self._data_block in data

    def _prepare_data(self, data: str):
        return data

    def _decrypt_response(self, data: dict) -> dict:
        return data
