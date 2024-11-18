from requests import post
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client_abstract import AbstractRouter


class TplinkC6V4Router(AbstractRouter):
    def supports(self) -> bool:
        url = '{}/?code=2&asyn=1'.format(self.host)
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
        raise ClientException('Not Implemented')

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
