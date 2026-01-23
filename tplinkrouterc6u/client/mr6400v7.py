"""
TP-Link TL-MR6400 v7 Client

Based on reverse-engineering of network traffic.
Protocol is similar to MR series but with differences in:
1. Login: Uses RSA encryption (PKCS1 v1.5) for both Username and Password
2. Password must be Base64 encoded before encryption
3. Actions: Uses /cgi endpoint with types in query string and plain text body
"""

from logging import Logger

from tplinkrouterc6u.client.mr import TPLinkMRClient
from tplinkrouterc6u.common.exception import ClientException, ClientError

from json import loads


class TPLinkMR6400v7Client(TPLinkMRClient):
    """Client for TP-Link MR6400 v7"""

    def __init__(self, host: str, password: str, username: str = '', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30):
        super().__init__(host, password, username, logger, verify_ssl, timeout)


    def _req_rsa_key(self):
        """
        Requests the RSA public key from the host

        Return value:
            ((n, e), seq) tuple
        """
        response = ''
        try:
            url = self._get_url(self._url_rsa_key)
            (code, response) = self._request(url)
            assert code == 200

            # assert return code
            assert self._parse_ret_val(response) == self.HTTP_RET_OK

            json_data = loads(response)

            ee = json_data['ee']
            nn = json_data['nn']
            seq = json_data['seq']

            assert ee and nn and seq
            assert len(ee) == 6
            assert len(nn) == 128

        except Exception as e:
            error = (self.ROUTER_NAME + '- {} - Unknown error rsa_key! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

        return nn, ee, int(seq)


    def _parse_ret_val(self, response_text):
        """
        Parses $.ret value from the response text

        Return value:
            return code (int)
        """
        if '[error]0' in response_text or 'errorcode=0' in response_text:
            return 0

        try:
            result = loads(response_text)

            result = result['ret']
            result = int(result)

            return result
        
        except ValueError:
                raise ClientError(f"Error trying to convert response to JSON: {response_text}")
