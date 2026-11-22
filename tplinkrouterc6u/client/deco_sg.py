"""Mercusys Halo / Deco LuCI with MD5 session hash and PKCS#1 v1.5 signatures.

Issue: https://github.com/AlexandrErohin/home-assistant-tplink-router/issues/437
"""

MERCUSYS_SG_VENDOR_REV = 'har-result-json-8'

# Match browser JSON.stringify (no spaces after ":" or ",").
_MERCUSYS_JSON_SEP = (',', ':')

from hashlib import md5
from json import dumps, loads
from re import search
from urllib.parse import quote

from requests import post
from requests.exceptions import Timeout

from tplinkrouterc6u.client.deco import TPLinkDecoClient
from tplinkrouterc6u.client.sg import TplinkRouterSG
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.exception import ClientException, ClientError


class TplinkDecoSGRouter(TPLinkDecoClient):
    """Deco-family API with SG encryption (Halo H60XR and similar)."""

    ROUTER_NAME = 'TP-Link Deco (SG encryption)'

    def _generate_aes_key(self) -> None:
        TplinkRouterSG._generate_aes_key(self)

    def _aes_encrypt(self, data: str) -> str:
        return TplinkRouterSG._aes_encrypt(self, data)

    def _aes_decrypt(self, data: str) -> str:
        return TplinkRouterSG._aes_decrypt(self, data)

    def _get_aes_formatted_key(self) -> str:
        return TplinkRouterSG._get_aes_formatted_key(self)

    @staticmethod
    def _rsa_v15_encrypt(data: str, n_hex: str, e_hex: str) -> str:
        return TplinkRouterSG._rsa_v15_encrypt(data, n_hex, e_hex)

    def _mercusys_rsa_signature(self, sign_str: str) -> str:
        """Chunked PKCS#1 v1.5 RSA, matching ``$.su.encryptor.getSignature``."""
        sign = ''
        pos = 0
        while pos < len(sign_str):
            sign += self._rsa_v15_encrypt(
                sign_str[pos:pos + 53], self._nn, self._ee)
            pos += 53
        return sign

    def _build_login_signature(self, data_len: int) -> str:
        sign_str = '{}&h={}&s={}'.format(
            self._get_aes_formatted_key(), self._hash, self._seq + data_len)
        return self._mercusys_rsa_signature(sign_str)

    def _build_request_signature(self, data_len: int) -> str:
        sign_str = 'h={}&s={}'.format(self._hash, self._seq + data_len)
        return self._mercusys_rsa_signature(sign_str)

    @staticmethod
    def _merge_path_and_body_params(path: str, data: str) -> tuple[str, str]:
        if data and data.lstrip().startswith('{'):
            return path, data
        return TplinkRouterSG._merge_path_and_body_params(path, data)

    @staticmethod
    def _outer_cipher(resp: dict) -> str:
        if not isinstance(resp, dict):
            raise ClientException('{} - invalid response envelope'.format(
                TplinkDecoSGRouter.ROUTER_NAME))
        payload = resp.get('data')
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            nested = payload.get('data')
            if isinstance(nested, str):
                return nested
        if isinstance(resp.get('result'), str):
            return resp['result']
        raise ClientException('{} - missing ciphertext in response'.format(
            TplinkDecoSGRouter.ROUTER_NAME))

    @staticmethod
    def _envelope_block(payload: dict) -> dict:
        """Mercusys / Deco LuCI uses ``result``; SG Archer firmware uses ``data``."""
        if not isinstance(payload, dict):
            raise ClientException('invalid JSON envelope')
        for key in ('result', 'data'):
            block = payload.get(key)
            if isinstance(block, dict):
                return block
        raise ClientException('response missing result/data block')

    def _mercusys_json_headers(self) -> dict:
        referer = self.host.rstrip('/') + '/webpages/index.html'
        return {
            'Content-Type': 'application/json',
            'Referer': referer,
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
        }

    def _read_login_envelope(self, form: str) -> dict:
        url = '{}/cgi-bin/luci/;stok=/login?form={}'.format(self.host, form)
        response = post(
            url,
            data=dumps({'operation': 'read'}, separators=_MERCUSYS_JSON_SEP),
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        try:
            return self._envelope_block(response.json())
        except Exception as e:
            raise ClientException(
                '{} - login?form={} read failed: {}; {}'.format(
                    self.ROUTER_NAME, form, e,
                    response.text[:200] if response.text else '',
                )) from e

    def _request_pwd_keys(self) -> None:
        block = self._read_login_envelope('keys')
        pwd = block.get('password')
        if not (isinstance(pwd, list) and len(pwd) >= 2):
            raise ClientException('{} - invalid password keys'.format(self.ROUTER_NAME))
        self._pwdNN, self._pwdEE = pwd[0], pwd[1]

    def _request_auth_keys(self) -> None:
        block = self._read_login_envelope('auth')
        key = block.get('key')
        if not (isinstance(key, list) and len(key) >= 2):
            raise ClientException('{} - invalid auth keys'.format(self.ROUTER_NAME))
        self._nn, self._ee = key[0], key[1]
        self._seq = block.get('seq', 0)

    def __init__(self, host: str, password: str, username: str = 'admin', logger=None,
                 verify_ssl: bool = True,
                 timeout: int = TPLinkDecoClient._DEFAULT_TIMEOUT) -> None:
        if timeout < TPLinkDecoClient._DEFAULT_TIMEOUT:
            timeout = TPLinkDecoClient._DEFAULT_TIMEOUT
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._init_sg_session_state()
        headers = self._mercusys_json_headers()
        self._headers_login = dict(headers)
        self._headers_request = dict(headers)

    def _init_sg_session_state(self) -> None:
        self._aes_key = ''
        self._aes_iv = ''
        self._hash = ''
        self._nn = ''
        self._ee = ''
        self._seq = 0

    def _reset_session(self) -> None:
        super()._reset_session()
        self._init_sg_session_state()

    def _get_login_payload(self, encrypted_pwd: str) -> str:
        """LuCI login AES plaintext (live Halo: ``params.password``, not flat HAR model)."""
        return dumps({
            'operation': 'login',
            'params': {'password': encrypted_pwd},
        }, separators=_MERCUSYS_JSON_SEP)

    @staticmethod
    def _extract_stok(decrypted: dict) -> str | None:
        if not isinstance(decrypted, dict):
            return None
        if decrypted.get('success'):
            data = decrypted.get('data')
            if isinstance(data, dict) and data.get('stok'):
                return data['stok']
        for block in ('result', 'data'):
            nested = decrypted.get(block)
            if isinstance(nested, dict) and nested.get('stok'):
                return nested['stok']
        return decrypted.get('stok')

    @staticmethod
    def _login_failed(decrypted: dict) -> str | None:
        if not isinstance(decrypted, dict):
            return 'invalid login response'
        if TplinkDecoSGRouter._extract_stok(decrypted):
            return None
        if decrypted.get('error_code') not in (None, 0):
            return 'error_code={}'.format(decrypted.get('error_code'))
        if decrypted.get('success') is False:
            error_data = decrypted.get('data') or {}
            if not isinstance(error_data, dict):
                error_data = {}
            return (decrypted.get('errorcode')
                    or error_data.get('errorcode')
                    or 'login failed')
        if decrypted.get('success') or decrypted.get('error_code') == 0:
            return None
        return 'login failed'

    def authorize(self) -> None:
        try:
            self._retry_request(self._authorize_fresh_sg)
        except Timeout as err:
            raise ClientException(
                'TplinkRouter - {} - authorize timed out after retries. '
                'If the Deco web UI still works, reboot the main node '
                '(power-cycle or Tether "Restart network").'
                .format(self.__class__.__name__)
            ) from err

    def _authorize_fresh_sg(self) -> None:
        self._reset_session()
        self._request_pwd_keys()
        self._request_auth_keys()
        self._generate_aes_key()
        encrypted_pwd = EncryptionWrapper.rsa_encrypt(
            self.password, self._pwdNN, self._pwdEE)
        # HAR: encryptor.setHash("admin", password) -> MD5(username + password)
        self._hash = md5(
            (self.username + self.password).encode()).hexdigest()
        self._login_with_hash(encrypted_pwd)

    def _login_with_hash(self, encrypted_pwd: str) -> None:
        encrypted_data = self._aes_encrypt(self._get_login_payload(encrypted_pwd))
        sign = self._build_login_signature(len(encrypted_data))
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)
        body = 'sign={}&data={}'.format(sign, quote(encrypted_data))
        response = post(
            url, data=body, headers=self._headers_login,
            timeout=self.timeout, verify=self._verify_ssl,
        )
        if not (response.text or '').strip():
            raise ClientException(
                '{} - Cannot authorize! Empty login response (HTTP {})'.format(
                    self.ROUTER_NAME, response.status_code))
        try:
            resp = response.json()
            decrypted = loads(self._aes_decrypt(self._outer_cipher(resp)))
            failure = self._login_failed(decrypted)
            if failure is not None:
                raise ClientException(
                    '{} - Login failed: {}'.format(self.ROUTER_NAME, failure))
            stok = self._extract_stok(decrypted)
            if not stok:
                raise ClientException(
                    '{} - Login response missing stok'.format(self.ROUTER_NAME))
            self._stok = stok
            if 'set-cookie' in response.headers:
                regex_result = search(
                    r'sysauth=([^;]+)', response.headers['set-cookie'])
                if regex_result:
                    self._sysauth = regex_result.group(1)
            self._logged = True
        except ClientException:
            raise
        except Exception as e:
            raise ClientException(
                '{} - Cannot authorize! Error - {}; HTTP {}; Response - {}'.format(
                    self.ROUTER_NAME, e, response.status_code,
                    response.text[:200] if response.text else '',
                )
            ) from e

    def request(self, path: str, data: str, ignore_response: bool = False,
                ignore_errors: bool = False) -> dict | None:
        return self._retry_request(
            self._request_with_reauth, path, data, ignore_response, ignore_errors)

    def _sg_request(self, path: str, data: str, ignore_response: bool = False,
                  ignore_errors: bool = False) -> dict | None:
        if not self._logged:
            raise ClientException('{} - not authorised'.format(self.ROUTER_NAME))

        path, data = TplinkDecoSGRouter._merge_path_and_body_params(path, data)
        encrypted_data = self._aes_encrypt(data)
        sign = self._build_request_signature(len(encrypted_data))

        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        body = 'sign={}&data={}'.format(sign, quote(encrypted_data))
        cookies = {'sysauth': self._sysauth} if self._sysauth else None

        response = post(
            url, data=body, headers=self._headers_request,
            cookies=cookies, timeout=self.timeout, verify=self._verify_ssl,
        )

        if ignore_response:
            return None

        resp = None
        decrypted_text = None
        try:
            resp = response.json()
            decrypted_text = self._aes_decrypt(self._outer_cipher(resp))
            decrypted = loads(decrypted_text)

            if self._is_valid_response(decrypted):
                self._remember_envelope(decrypted)
                return decrypted.get(self._data_block, decrypted)
            if ignore_errors:
                return decrypted
        except Exception as e:
            error = ('{} - Unknown response - {}; Request {} - Response {}'
                     .format(self.ROUTER_NAME, e, path,
                             response.text[:200] if response.text else ''))
            if decrypted_text:
                error += ' Decrypted response - {}'.format(decrypted_text)
            if self._logger:
                self._logger.debug(error)
            raise ClientError(error)

        error = ('{} - Response with error; Request {} - Response {}'
                 .format(self.ROUTER_NAME, path,
                         response.text[:200] if response.text else ''))
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def _request_with_reauth(self, path: str, data: str, ignore_response: bool = False,
                             ignore_errors: bool = False) -> dict | None:
        try:
            return self._sg_request(path, data, ignore_response, ignore_errors)
        except ClientError:
            self.authorize()
            return self._sg_request(path, data, ignore_response, ignore_errors)

    def get_lte_status(self):
        raise NotImplementedError

    def supports(self) -> bool:
        if len(self.password) > 125:
            return False
        try:
            self._request_pwd_keys()
            self._request_auth_keys()
        except Exception:
            return False
        try:
            self.authorize()
            self.request(
                'admin/network?form=wan_ipv4',
                dumps({'operation': 'read'}, separators=_MERCUSYS_JSON_SEP),
            )
            try:
                self.logout()
            except (ClientException, ClientError):
                pass
            return True
        except Exception:
            self._reset_session()
            return False