import hmac
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

SG_CERTIFICATIONS = ['SG CLS L1 STAGE2', 'EU CE RED']
SIGNATURE_OFFSET = 53
AES_KEY_LEN = 16

class TplinkRouterSG(TplinkBaseRouter):
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
        if len(self.password) > 125: return False
        try:
            return self._check_sg_certification()
        except Exception: return False

    def _check_sg_certification(self) -> bool:
        url = '{}/cgi-bin/luci/;stok=/device_config?form=config'.format(self.host)
        response = post(url, data='operation=read', headers=self._headers_login,
                        timeout=self.timeout, verify=self._verify_ssl)
        try:
            data = response.json()
            certs = data.get('data', {}).get('certification', [])
            return any(c in SG_CERTIFICATIONS for c in certs)
        except Exception: return False

    def _generate_aes_key(self) -> None:
        self._aes_key = ''.join([str(randint(0, 9)) for _ in range(AES_KEY_LEN)])
        self._aes_iv = ''.join([str(randint(0, 9)) for _ in range(AES_KEY_LEN)])

    def _aes_encrypt(self, data: str) -> str:
        cipher = AES.new(self._aes_key.encode(), AES.MODE_CBC, self._aes_iv.encode())
        return b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

    def _aes_decrypt(self, data: str) -> str:
        cipher = AES.new(self._aes_key.encode(), AES.MODE_CBC, self._aes_iv.encode())
        return unpad(cipher.decrypt(b64decode(data)), AES.block_size).decode()

    @staticmethod
    def _rsa_v15_encrypt(data: str, n_hex: str, e_hex: str) -> str:
        key = construct((int(n_hex, 16), int(e_hex, 16)))
        cipher = PKCS1_v1_5.new(key)
        result = hexlify(cipher.encrypt(data.encode())).decode()
        key_len = len(n_hex)
        return result.zfill(key_len) if len(result) < key_len else result

    @staticmethod
    def _rsa_oaep_encrypt(data: str, n_hex: str, e_hex: str) -> str:
        key = construct((int(n_hex, 16), int(e_hex, 16)))
        cipher = PKCS1_OAEP.new(key)
        result = hexlify(cipher.encrypt(data.encode())).decode()
        key_len = len(n_hex)
        return result.zfill(key_len) if len(result) < key_len else result

    def _get_aes_formatted_key(self) -> str:
        return 'k={}&i={}'.format(self._aes_key, self._aes_iv)

    def _request_pwd_keys(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)
        response = post(url, params={'operation': 'read'}, timeout=self.timeout, verify=self._verify_ssl)
        try:
            data = response.json()
            self._pwdNN = data['data']['password'][0]
            self._pwdEE = data['data']['password'][1]
        except Exception as e: raise ClientException(f'TplinkRouterSG - Failed to get password keys: {e}')

    def _request_auth_keys(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)
        response = post(url, params={'operation': 'read'}, timeout=self.timeout, verify=self._verify_ssl)
        try:
            data = response.json()
            self._seq = data['data']['seq']
            self._nn = data['data']['key'][0]
            self._ee = data['data']['key'][1]
        except Exception as e: raise ClientException(f'TplinkRouterSG - Failed to get auth keys: {e}')

    def _build_login_signature(self, data_len: int) -> str:
        sign_str = '{}&h={}&s={}'.format(self._get_aes_formatted_key(), self._hash, self._seq + data_len)
        sign = ''
        for i in range(0, len(sign_str), SIGNATURE_OFFSET):
            chunk = sign_str[i:i + SIGNATURE_OFFSET]
            sign += self._rsa_oaep_encrypt(chunk, self._nn, self._ee)
        return sign

    def _build_request_signature(self, data_len: int) -> str:
        sign_str = 'h={}&s={}'.format(self._hash, self._seq + data_len)
        aes_key = self._get_aes_formatted_key()
        sign = ''
        for i in range(0, len(sign_str), SIGNATURE_OFFSET):
            chunk = sign_str[i:i + SIGNATURE_OFFSET]
            h = hmac.new(aes_key.encode(), chunk.encode(), sha256)
            sign += h.hexdigest()
        return sign

    def authorize(self) -> None:
        self._request_pwd_keys()
        self._request_auth_keys()
        self._hash = sha256((self.username + self.password).encode()).hexdigest()
        self._generate_aes_key()
        encrypted_pwd = self._rsa_v15_encrypt(self.password, self._pwdNN, self._pwdEE)
        login_data = 'operation=login&password={}&confirm=true'.format(encrypted_pwd)
        encrypted_data = self._aes_encrypt(login_data)
        sign = self._build_login_signature(len(encrypted_data))
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)
        body = {'sign': sign, 'data': encrypted_data}
        response = post(url, data=body, headers=self._headers_login, timeout=self.timeout, verify=self._verify_ssl)
        try:
            resp = response.json()
            decrypted = json.loads(self._aes_decrypt(resp['data']))
            if 'success' in decrypted and decrypted['success']:
                self._stok = decrypted['data']['stok']
                if 'set-cookie' in response.headers:
                    regex_result = search(r'sysauth=([^;]+)', response.headers['set-cookie'])
                    if regex_result: self._sysauth = regex_result.group(1)
                self._logged = True
            else: raise ClientException('TplinkRouterSG - Login failed')
        except Exception as e: raise ClientException(f'TplinkRouterSG - Cannot authorize! Error - {e}')

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        if self._logged is False: raise Exception('Not authorised')
        encrypted_data = self._aes_encrypt(data)
        self._hash = sha256(encrypted_data.encode()).hexdigest()
        sign = self._build_request_signature(len(encrypted_data))
        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        
        # SURGICAL OPERATION LOGIC:
        # BE-series requires dictionary format and explicit Content-Type for WRITE.
        # But REJECTS the header for READ (get_firmware, etc).
        is_write = 'operation=write' in data or 'operation=save' in data or 'operation=update' in data
        
        hdrs = self._headers_request.copy()
        if is_write:
            body = {'sign': sign, 'data': encrypted_data}
            hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            body = 'sign={}&data={}'.format(sign, quote(encrypted_data))
            
        response = post(url, data=body, headers=hdrs, cookies={'sysauth': self._sysauth},
                        timeout=self.timeout, verify=self._verify_ssl)
                        
        if ignore_response: return None
        try:
            resp = response.json()
            decrypted = json.loads(self._aes_decrypt(resp['data']))
            if 'success' in decrypted and decrypted['success']:
                return decrypted.get(self._data_block, decrypted)
            elif ignore_errors: return decrypted
        except Exception as e: raise ClientError(f'TplinkRouterSG - Unknown response - {e}')
        raise ClientError(f'TplinkRouterSG - Response with error; Request {path} - Response {response.text[:200]}')
