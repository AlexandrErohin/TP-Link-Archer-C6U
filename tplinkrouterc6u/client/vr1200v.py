import re
from base64 import b64encode
from datetime import datetime, timedelta
from hashlib import md5
from time import sleep
from requests import Response
from tplinkrouterc6u.client.ex import TPLinkEXClient
from tplinkrouterc6u.common.exception import ClientException


class TplinkVR1200vRouter(TPLinkEXClient):
    def authorize(self) -> None:
        if self._token is not None and self._authorized_at >= (datetime.now() - timedelta(seconds=3)):
            return
        self._token = None

        self._nn, self._ee, self._seq = self._req_rsa_key()

        # Custom login because VR1200v returns unencrypted $.ret=0; and standard _req_login crashes on it
        login_data = ('{"data":{"UserName":"%s","Passwd":"%s","Action": "1","stack":"0,0,0,0,0,0",'
                      '"pstack":"0,0,0,0,0,0"},"operation":"cgi","oid":"/cgi/login"}') % (
            b64encode(bytes(self.username, "utf-8")).decode("utf-8"),
            b64encode(bytes(self.password, "utf-8")).decode("utf-8")
        )

        sign, data = self._prepare_data(login_data, True)
        request_data = f"sign={sign}\r\ndata={data}\r\n"
        url = f"{self.host}/cgi_gdpr?9"

        (code, response) = self._request(url, data_str=request_data)

        # Try to parse it directly first, as VR1200v returns $.ret=0; directly
        ret_code = None
        if "$.ret=" in response:
            ret_code = self._parse_ret_val(response)
        else:
            response = self._encryption.aes_decrypt(response)
            ret_code = self._parse_ret_val(response)

        if ret_code != self.HTTP_RET_OK:
            raise ClientException(f"VR1200v Login failed. Error code: {ret_code}")

        self._token = self._req_token()
        self._authorized_at = datetime.now()

        # Override hash for subsequent requests: VR1200v uses MD5(username + token)
        self._hash = md5(f"{self.username}{self._token}".encode('utf-8')).hexdigest()

    def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
        """
        Overrides the _request method to handle the specific AES response body parsing of VR1200v
        """
        headers = self.HEADERS.copy()

        # add referer to request headers, MUST HAVE trailing slash for VR1200v
        headers['Referer'] = f"{self.host}/"

        if self._token is not None:
            headers['TokenID'] = self._token

        if encrypt:
            sign, data = self._prepare_data(data_str, is_login)
            data = f"sign={sign}\r\ndata={data}\r\n"
        else:
            data = data_str

        retry = 0
        r = Response()

        while retry < self.REQUEST_RETRIES:
            if method == 'POST':
                r = self.req.post(url, data=data, headers=headers, timeout=self.timeout, verify=self._verify_ssl)
            elif method == 'GET':
                r = self.req.get(url, data=data, headers=headers, timeout=self.timeout, verify=self._verify_ssl)
            else:
                raise Exception('Unsupported method ' + str(method))

            if (r.status_code not in [500, 406]
                    and '<title>500 Internal Server Error</title>' not in r.text
                    and '<title>406 Not Acceptable</title>' not in r.text):
                break

            sleep(0.1)
            retry += 1

        if encrypt and (r.status_code == 200) and (r.text != ''):
            b64_match = re.search(r'([a-zA-Z0-9+/=]{15,})', r.text)
            if b64_match:
                return r.status_code, self._encryption.aes_decrypt(b64_match.group(1))
            return r.status_code, r.text
        else:
            return r.status_code, r.text
