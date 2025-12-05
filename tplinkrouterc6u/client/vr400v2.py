"""
TP-Link Archer VR400 v2 Client

Based on reverse-engineering of network traffic.
Protocol is similar to MR series but with differences in:
1. Login: Uses RSA encryption (PKCS1 v1.5) for both Username and Password
2. Password must be Base64 encoded before encryption
3. Actions: Uses /cgi endpoint with types in query string and plain text body
"""

from re import search
from base64 import b64encode
from logging import Logger

from tplinkrouterc6u.client.mr import TPLinkMRClient
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.common.encryption import EncryptionWrapper


class TPLinkVR400v2Client(TPLinkMRClient):
    """Client for TP-Link Archer VR400 v2"""

    def __init__(self, host: str, password: str, username: str = '', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30):
        # VR400v2 doesn't validate username, so we forward the provided username to parent
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        # Set User-Agent to look like a browser (required for some routers)
        self.req.headers['User-Agent'] = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        )

    def _req_rsa_key(self):
        """
        Requests the RSA public key from the host
        VR400 v2 specific:
        - Response does NOT contain 'seq' variable
        - Returns dummy seq=0
        """
        response = ''
        try:
            url = self._get_url(self._url_rsa_key)
            (code, response) = self._request(url)
            if code != 200:
                raise ClientException(f'RSA key request failed with status code {code}')

            # Check return code
            ret_val = self._parse_ret_val(response)
            if ret_val != self.HTTP_RET_OK:
                raise ClientException(f'RSA key request failed with return code {ret_val}')

            # parse public key
            ee = search('var ee="(.*)";', response)
            nn = search('var nn="(.*)";', response)

            if not ee or not nn:
                raise ClientException('Could not parse RSA public key from response')
            ee = ee.group(1)
            nn = nn.group(1)

            return nn, ee, 0  # Dummy seq

        except Exception as e:
            error = (
                'TplinkRouter - {} - Unknown error rsa_key! Error - {}; Response - {}'
                .format(self.__class__.__name__, e, response)
            )
            if self._logger:
                self._logger.debug(error)
            # Re-raise nicely formatted exception if it wasn't already a ClientException
            if isinstance(e, ClientException):
                raise e
            raise ClientException(error)

    def _req_login(self) -> None:
        """
        Authenticates to the host
        VR400 v2 specific:
        - Encrypts Username and Password separately using RSA (PKCS1 v1.5)
        - Password MUST be base64 encoded first
        - Sends them as query parameters
        """
        # Encrypt username (dummy) and password
        # Use PKCS1 v1.5 padding (via EncryptionWrapper)
        # Router requires UserName parameter but doesn't validate it, so we use 'admin'
        encrypted_username = EncryptionWrapper.rsa_encrypt('admin', self._nn, self._ee)

        # Password must be base64 encoded first!
        b64_password = b64encode(self.password.encode('utf-8')).decode('utf-8')
        encrypted_password = EncryptionWrapper.rsa_encrypt(b64_password, self._nn, self._ee)

        # Prepare data
        params = {
            'UserName': encrypted_username,
            'Passwd': encrypted_password,
            'Action': '1',
            'LoginStatus': '0'
        }

        # Send login request
        # Note: MR base _get_url adds timestamp automatically
        url = self._get_url('cgi/login', params)
        (code, response) = self._request(url, method='POST')

        if code != 200:
            raise ClientException(f"Login request failed with status {code}")

        # parse and match return code
        ret_code = self._parse_ret_val(response)

        if ret_code == self.HTTP_RET_OK:
            return

        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
            raise ClientException('Login failed, wrong password.')

        if ret_code == -1:
            if self._logger:
                self._logger.warning(f"Login returned -1. Response: {response}")
                self._logger.warning("Proceeding anyway...")
            return

        raise ClientException(f'Login failed. Error code: {ret_code}')

    def req_act(self, acts: list):
        """
        Requests ACTs via the /cgi endpoint
        VR400 v2 specific:
        - URL: /cgi?type1&type2...
        - Body: Plain text [SECTION#...]...
        """
        # Auto-authorize if not already authorized
        if self._token is None:
            self.authorize()

        act_types = [str(act.type) for act in acts]

        # Build body string
        act_data = []
        for i, act in enumerate(acts):
            attrs_str = '\r\n'.join(act.attrs)
            act_data.append(f'[{act.oid}#{act.stack}#{act.pstack}]{i},{len(act.attrs)}\r\n{attrs_str}\r\n')

        data = ''.join(act_data)
        query_str = '&'.join(act_types)
        url = f"{self.host}/cgi?{query_str}"

        # Send request (encrypt=False - using plain HTTP for VR400v2 actions)
        (code, response) = self._request(url, method='POST', data_str=data, encrypt=False)

        if code != 200:
            error = f'Response with error; Request {data} - Response {response}'
            if self._logger:
                self._logger.debug(error)
            raise ClientError(error)

        result = self._merge_response(response)

        return response, result.get('0') if len(result) == 1 and result.get('0') else result

    def _req_token(self):
        """
        Requests the TokenID
        VR400 v2 specific: Handles spaces in var declaration
        """
        url = self._get_url('')
        (code, response) = self._request(url, method='GET')
        if code != 200:
            raise ClientException(f'Token request failed with status code {code}')

        # Allow spaces around = and optional semicolon, non-greedy match for value
        result = search(r'var\s+token\s*=\s*"([^"]+)"', response)

        if result is None:
            if self._logger:
                self._logger.debug(f"Token not found in response: {response[:200]}...")
            raise ClientException("Token not found in response")

        token = result.group(1)
        if not token:
            raise ClientException("Token is empty")

        return token

    def _parse_ret_val(self, response_text):
        """
        Parses return value from the response text
        VR400 v2 specific: Handles multiple formats
        """
        # Try $.ret=...; format (Standard for VR400 v2)
        result = search(r'\$\.ret=([-]?\d+);', response_text)
        if result:
            return int(result.group(1))

        # Try [error]... format (VR series)
        result = search(r'\[error\](\d+)', response_text)
        if result:
            return int(result.group(1))

        # Try var errorcode=... format
        result = search(r'var\s+errorcode\s*=\s*(\d+)', response_text)
        if result:
            return int(result.group(1))

        # If we can't find it, but response seems OK (e.g. contains data), return 0
        if '[error]0' in response_text or 'errorcode=0' in response_text:
            return 0

        # If we really can't find it, log and raise
        if self._logger:
            self._logger.debug(f"Could not parse return code from: {response_text[:100]}...")

        # Fallback to base implementation which will raise error
        return super()._parse_ret_val(response_text)
