from urllib.parse import urlencode
from requests import post, Response
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client.c1200 import TplinkC1200Router


class TplinkCloudLoginRouter(TplinkC1200Router):
    """Login with a TP-Link ID (cloud account) instead of the local password.

    Once a router is bound to a TP-Link ID, its web UI only shows the TP-Link ID form and the
    local form (login?form=login) rejects the owner's credentials. The web UI logs in through
    login?form=cloud_login instead: it reads the RSA key from that form and posts the email as
    username plus the password encrypted with RSA PKCS#1 v1.5. This client does the same, so the
    plain TP-Link ID email and password can be used. Picked when the username is an email.
    """

    def supports(self) -> bool:
        if '@' not in (self.username or ''):
            return False
        try:
            self._request_pwd()
            return True
        except ClientException:
            return False

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=cloud_login'.format(self.host)
        response = post(
            url,
            data='operation=read',
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            args = response.json()[self._data_block]['password']
            self._pwdNN = args[0]
            self._pwdEE = args[1]
        except Exception as e:
            error = ('TplinkRouter - {} - Unknown error for pwd! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _try_login(self) -> Response:
        url = '{}/cgi-bin/luci/;stok=/login?form=cloud_login'.format(self.host)
        body = urlencode({
            'operation': 'login',
            'username': self.username,
            'password': EncryptionWrapper.rsa_encrypt(self.password, self._pwdNN, self._pwdEE),
        })

        return post(
            url,
            data=body,
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
