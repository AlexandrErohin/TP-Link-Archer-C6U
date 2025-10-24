import base64
from tplinkrouterc6u.common.exception import ClientException, AuthorizeError
from tplinkrouterc6u.client.mr import TPLinkMRClient
from Crypto.PublicKey import RSA
from re import search
from binascii import hexlify
from Crypto.Cipher import PKCS1_v1_5


class TPLinkMR200Client(TPLinkMRClient):

    def authorize(self) -> None:
        params = self.__get_params()

        # Construct the RSA public key manually using modulus (n) and exponent (e)
        n = int(params["nn"])
        e = int(params["ee"])
        pub_key = RSA.construct((n, e))

        # Create an RSA cipher with PKCS#1 v1.5 padding (same as rsa.encrypt)
        cipher = PKCS1_v1_5.new(pub_key)

        # Encrypt username
        rsa_username = cipher.encrypt(self.username.encode("utf-8"))
        rsa_username_hex = hexlify(rsa_username).decode("utf-8")

        # Encrypt password (after base64 encoding, as in your original code)
        rsa_password = cipher.encrypt(base64.b64encode(self.password.encode("utf-8")))
        rsa_password_hex = hexlify(rsa_password).decode("utf-8")

        # Send login request
        self.req.post(
            f'{self.host}/cgi/login?UserName={rsa_username_hex}&Passwd={rsa_password_hex}&Action=1&LoginStatus=0'
        )

        # Try to extract token
        r = self.req.get(self.host)
        try:
            self._token = search(r'var token="(.*)";', r.text).group(1)
        except AttributeError:
            raise AuthorizeError()

    def __get_params(self, retry=False):
        try:
            r = self.req.get(f"{self.host}/cgi/getParm", timeout=5)
            result = {}
            for line in r.text.splitlines()[0:2]:
                match = search(r"var (.*)=\"(.*)\"", line)
                result[match.group(1)] = int(match.group(2), 16)
            return result
        except Exception:
            if not retry:
                return self.__get_params(True)
            raise ClientException()

    def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
        return super()._request(url, method, data_str, False, is_login)
