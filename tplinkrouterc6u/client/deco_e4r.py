from hashlib import md5
from json import loads
from logging import Logger
from urllib import parse
import requests
from requests import Session
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.client.deco import TPLinkDecoClient


class TplinkDecoE4RRouter(TPLinkDecoClient):
    """Client for the TP-Link Deco E4R.

    The E4R does not expose the luci ``/cgi-bin/luci/;stok=`` JSON login used by
    :class:`TPLinkDecoClient`. Instead it authenticates through the
    ``/?code=N&asyn=M&id=TOKEN`` protocol (same family as
    :class:`~tplinkrouterc6u.client.c80.TplinkC80Router` and
    :class:`~tplinkrouterc6u.client.re330.TplinkRE330Router`). Once logged in the
    data layer is the ordinary Deco JSON API (``/admin/...?form=...``), so all of
    the parsing in :class:`TPLinkDecoClient` is reused as-is; only the login
    handshake and the request transport are overridden here.
    """

    ROUTER_NAME = 'TP-Link Deco E4R'
    # RSA-512 PKCS#1 v1.5 limits the login password to 53 UTF-8 bytes.
    _MAX_PASSWORD_BYTES = 53
    PAD_CHAR = chr(187)

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self.host = self.host.rstrip('/')
        self._session = Session()
        if self._verify_ssl is False:
            self._session.verify = False
        # AES session cipher (self._encryption is created by TplinkEncryption).
        self._nn = ''
        self._ee = ''
        self._seq = ''
        self._token = ''
        self._headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': self.host + '/',
        }

    def supports(self) -> bool:
        if len(self.password.encode('utf-8')) > self._MAX_PASSWORD_BYTES:
            return False

        try:
            self.authorize()
            return True
        except Exception:
            return False

    def authorize(self) -> None:
        if len(self.password.encode('utf-8')) > self._MAX_PASSWORD_BYTES:
            raise ClientException(
                '{} - password exceeds the RSA-512 limit ({} bytes)'
                .format(self.ROUTER_NAME, self._MAX_PASSWORD_BYTES))

        # 1) getTmpKey - unauthenticated challenge carrying the token key material.
        response = self._code_request('code=7&asyn=1')
        text = response.text
        if text.endswith('\r\n'):
            text = text[:-2]
        lines = text.split('\r\n')
        if len(lines) < 5:
            raise ClientException('{} - unexpected challenge response'.format(self.ROUTER_NAME))
        key_string, alphabet = lines[3], lines[4]

        # id = securityEncode(line3, key=MD5(password), alphabet=line4)
        password_hash = md5(self.password.encode()).hexdigest()
        self._token = parse.quote(self._security_encode(key_string, password_hash, alphabet), safe='!()*')

        # 2) GDPR ack (best effort - kept to mirror the web UI handshake).
        self._code_request('code=16&asyn=0', data='enable')

        # 3) Fetch the session RSA key and sequence number.
        response = self._code_request('code=16&asyn=0', data='get')
        key_data = response.text.split('\r\n')
        if len(key_data) < 4 or key_data[0] != '00000':
            raise ClientException('{} - invalid response for RSA keys'.format(self.ROUTER_NAME))
        self._ee, self._nn, self._seq = key_data[1], key_data[2], key_data[3]
        self._encryption = EncryptionWrapper()

        # 4) Login - the credential is the RSA-encrypted password.
        response = self._code_request('code=7&asyn=0', data=self._rsa_encrypt(self.password), use_token=True)
        if response.text.split('\r\n')[0] != '00000':
            raise ClientException('{} - login failed, check the router password'.format(self.ROUTER_NAME))

        # 5) Register the AES session key for subsequent encrypted requests.
        aes_string = self._encryption._get_aes_string()
        response = self._code_request('code=16&asyn=0', data='set ' + self._rsa_encrypt(aes_string), use_token=True)
        if response.text.split('\r\n')[0] != '00000':
            raise ClientException('{} - failed to register the session key'.format(self.ROUTER_NAME))

        self._logged = True

    def logout(self) -> None:
        self._code_request('code=11&asyn=0', use_token=True)
        self._token = ''
        self._logged = False

    def request(self, path: str, data: str, ignore_response: bool = False,
                ignore_errors: bool = False) -> dict | None:
        return self._retry_request(self._do_request, path, data, ignore_response, ignore_errors)

    def _do_request(self, path: str, data: str, ignore_response: bool = False,
                    ignore_errors: bool = False) -> dict | None:
        if self._logged is False:
            raise ClientException('{} - not authorised'.format(self.ROUTER_NAME))

        encrypted = self._encryption.aes_encrypt(data)
        body = 'sign={}&data={}'.format(self._signature(len(encrypted)), encrypted)

        separator = '&' if '?' in path else '?'
        url = '{}/{}{}id={}'.format(self.host, path, separator, self._token)

        response = self._session.post(url, data=body, headers=self._headers,
                                      timeout=self.timeout, verify=self._verify_ssl)

        if ignore_response:
            return None

        error = ''
        parsed = None
        decrypted = None
        try:
            decrypted = self._encryption.aes_decrypt(response.text)
            parsed = loads(decrypted)
            if self._is_valid_response(parsed):
                return parsed.get(self._data_block)
            elif ignore_errors:
                return parsed
        except Exception as e:
            error = ('{} - An unknown response - {}; Request {} - Response {}'
                     .format(self.ROUTER_NAME, e, path, response.text))
            if decrypted is not None:
                error += ' Decrypted response - {}'.format(decrypted)
        if not error:
            error = ('{} - Response with error; Request {} - Response {}'
                     .format(self.ROUTER_NAME, path, parsed))
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def _security_encode(self, text: str, key: str, alphabet: str) -> str:
        length = max(len(key), len(text))
        text = text.ljust(length, self.PAD_CHAR)
        key = key.ljust(length, self.PAD_CHAR)
        return ''.join(alphabet[(ord(text[i]) ^ ord(key[i])) % len(alphabet)] for i in range(length))

    def _rsa_encrypt(self, text: str) -> str:
        return EncryptionWrapper.rsa_encrypt(text, self._nn, self._ee)

    def _signature(self, data_length: int) -> str:
        payload = '{}&s={}'.format(self._encryption._get_aes_string(), int(self._seq) + data_length)
        signature = ''
        position = 0
        while position < len(payload):
            signature += self._rsa_encrypt(payload[position:position + 53])
            position += 53
        return signature

    def _code_request(self, query: str, data: str = None, use_token: bool = False):
        url = '{}/?{}'.format(self.host, query)
        if use_token:
            url += '&id={}'.format(self._token)
        try:
            return self._session.post(url, data=data, headers=self._headers,
                                      timeout=self.timeout, verify=self._verify_ssl)
        except requests.exceptions.RequestException as e:
            if self._logger:
                self._logger.error('{} - Network error: {}'.format(self.ROUTER_NAME, e))
            raise ClientException('{} - Network error: {}'.format(self.ROUTER_NAME, e)) from e
