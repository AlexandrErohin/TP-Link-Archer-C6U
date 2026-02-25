from base64 import b64encode
from http import HTTPStatus
from logging import Logger
from tplinkrouterc6u.client.ex import TPLinkEXClientGCM
from tplinkrouterc6u.common.encryption import EncryptionWrapperMRGCMOAEP
from tplinkrouterc6u.common.exception import ClientException


class TPLinkVX220Client(TPLinkEXClientGCM):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30):
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._encryption = EncryptionWrapperMRGCMOAEP()

    def supports(self):
        return self._verify_router() and super().supports()

    def _req_login(self) -> None:
        login_data = ('{"data":{"UserName":"%s","Passwd":"%s","Action": "1","stack":"0,0,0,0,0,0",'
                      '"pstack":"0,0,0,0,0,0"},"operation":"cgi","oid":"/cgi/login"}') % (
            b64encode(bytes(self.username, "utf-8")).decode("utf-8"),
            b64encode(bytes(self.password, "utf-8")).decode("utf-8")
        )

        sign, data, tag = self._prepare_data(login_data, True)

        request_data = f"sign={sign}\r\ndata={data}\r\ntag={tag}\r\n"

        url = f"{self.host}/cgi_gdpr?9"
        (code, response) = self._request(url, data_str=request_data)
        response = self._encryption.aes_decrypt(response)

        ret_code = self._parse_ret_val(response)
        error = ''
        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
            error = ('TplinkRouter - EX - Login failed, wrong user or password. '
                     'Try to pass user instead of admin in username')
        elif ret_code == self.HTTP_ERR_USER_BAD_REQUEST:
            error = 'TplinkRouter - EX - Login failed. Generic error code: {}'.format(ret_code)
        elif ret_code != self.HTTP_RET_OK:
            error = 'TplinkRouter - EX - Login failed. Unknown error code: {}'.format(ret_code)

        if error:
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _verify_router(self) -> bool:
        is_VX220 = False
        has_url_rsa_endpoint = False

        try:
            status_code, response = self._request(self.host, method='GET')
        except Exception as e:
            if self._logger is not None:
                self._logger.error("Error while checking modem: {}".format(e))
            return False

        if status_code == HTTPStatus.OK:
            is_VX220 = "VX220" in response
            has_url_rsa_endpoint = self._url_rsa_key in response

        if has_url_rsa_endpoint and is_VX220:
            return True
        elif is_VX220:
            try:
                status_code, response = self._request("{}/js/lib.js".format(self.host), method='GET')
            except Exception as e:
                if self._logger is not None:
                    self._logger.error("Error while checking if lib.js is present in modem: {}".format(e))
                return False

            if status_code == HTTPStatus.OK:
                has_url_rsa_endpoint = (self._url_rsa_key in response)

            return is_VX220 and has_url_rsa_endpoint
        else:
            return False
