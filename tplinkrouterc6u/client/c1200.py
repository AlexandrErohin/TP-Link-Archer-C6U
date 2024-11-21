from re import search
from requests import post, Response
from urllib.parse import urlencode
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.exception import ClientException, AuthorizeError
from tplinkrouterc6u.client.c5400x import TplinkC5400XRouter
from tplinkrouterc6u.common.dataclass import VPNStatus
from tplinkrouterc6u.common.package_enum import VPN


class TplinkC1200Router(TplinkC5400XRouter):
    username = ''
    password = ''
    _pwdNN = ''
    _pwdEE = ''
    _encryption = EncryptionWrapper()

    def supports(self) -> bool:
        if len(self.password) > 125:
            return False

        try:
            self._request_pwd()
            return True
        except ClientException:
            return False

    def authorize(self) -> None:
        if self._pwdNN == '':
            self._request_pwd()

        response = self._try_login()

        is_valid_json = False
        try:
            response.json()
            is_valid_json = True
        except BaseException:
            """Ignore"""

        if is_valid_json is False or response.status_code == 403:
            self._logged = False
            self._request_pwd()
            response = self._try_login()

        data = response.text
        try:
            data = response.json()
            data = self._decrypt_response(data)

            self._stok = data[self._data_block]['stok']
            regex_result = search(
                'sysauth=(.*);', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._logged = True

        except Exception as e:
            error = ("TplinkRouter - C1200 - Cannot authorize! Error - {}; Response - {}".format(e, data))
            if self._logger:
                self._logger.debug(error)
            if 'data' in vars() and data.get('errorcode') == 'login failed':
                raise AuthorizeError(error)
            raise ClientException(error)

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)
        response = post(
            url, params={'operation': 'read'},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()

            args = data[self._data_block]['password']

            self._pwdNN = args[0]
            self._pwdEE = args[1]

        except Exception as e:
            error = ('TplinkRouter - C1200 - {} - Unknown error for pwd! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _try_login(self) -> Response:
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        crypted_pwd = self._encryption.encrypt_password_C1200(self.password, self._pwdNN, self._pwdEE)

        body = self._get_login_data(crypted_pwd)

        return post(
            url,
            data=body,
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    @staticmethod
    def _get_login_data(crypted_pwd: str) -> str:
        return 'operation=login&password={}'.format(crypted_pwd)

    def get_vpn_status(self) -> VPNStatus:
        status = VPNStatus()

        values = [
            self.request("/admin/openvpn?form=config&operation=read", "operation=read"),
            self.request("/admin/pptpd?form=config&operation=read", "operation=read"),
            self.request("/admin/vpnconn?form=config&operation=list&vpntype=openvpn",
                         "operation=list&operation=list&vpntype=openvpn"),
            self.request("/admin/vpnconn?form=config&operation=list&vpntype=pptp",
                         "operation=list&operation=list&vpntype=pptp"),
        ]

        status.openvpn_enable = values[0]['enabled'] == 'on'
        status.pptpvpn_enable = values[1]['enabled'] == 'on'

        if isinstance(values[2], list):
            status.openvpn_clients_total = len(values[2])
            status.pptpvpn_clients_total = len(values[3])
        else:
            status.openvpn_clients_total = 0
            status.pptpvpn_clients_total = 0

        return status

    def set_vpn(self, vpn: VPN, enable: bool) -> None:
        path = "/admin/{}?form=config&operation=read".format(vpn.lowercase)
        current_config = self.request(path, "operation=read")
        current_config['enabled'] = "on" if enable else "off"
        data = urlencode(current_config)
        data = "&operation=write&{}".format(data)
        path = "/admin/{}?form=config{}".format(vpn.lowercase, data)
        self.request(path, data)
