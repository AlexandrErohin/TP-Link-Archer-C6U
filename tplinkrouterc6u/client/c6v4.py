from requests import post
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client_abstract import AbstractRouter


class TplinkC6V4Router(AbstractRouter):
    def supports(self) -> bool:
        url = '{}/?code=16&asyn=0'.format(self.host)
        try:
            response = post(url, timeout=self.timeout, verify=self._verify_ssl)
        except BaseException:
            return False
        if response.status_code == 401 and response.text.startswith('00'):
            raise ClientException(('Your router is not supported. Please add your router support to '
                                   'https://github.com/AlexandrErohin/TP-Link-Archer-C6U '
                                   'by implementing methods for TplinkC6V4Router class'
                                   ))
        return False

    def authorize(self) -> None:
        if self._pwdNN == '':
            self._request_pwd()

        if self._seq == '':
            self._request_seq()

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
            self._request_seq()
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
            error = ("TplinkRouter - {} - Cannot authorize! Error - {}; Response - {}"
                     .format(self.__class__.__name__, e, data))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)
        

    def logout(self) -> None:
        raise ClientException('Not Implemented')

    def get_firmware(self) -> Firmware:
        raise ClientException('Not Implemented')

    def get_status(self) -> Status:
        raise ClientException('Not Implemented')

    def reboot(self) -> None:
        raise ClientException('Not Implemented')

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        raise ClientException('Not Implemented')
