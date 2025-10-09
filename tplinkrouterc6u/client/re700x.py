from hashlib import md5
from re import search
from json import loads
from urllib.parse import urlencode
from requests import post, Response
from macaddress import EUI48
from ipaddress import IPv4Address
from logging import Logger

from tplinkrouterc6u.client.c6u import TplinkEncryption, TplinkBaseRouter
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.package_enum import Connection, VPN
from tplinkrouterc6u.common.dataclass import (
    Firmware,
    Status,
    Device,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
    VPNStatus,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.client_abstract import AbstractRouter
from abc import abstractmethod


class TplinkRe700XRouter(TplinkEncryption, TplinkBaseRouter):
    def __init__(self, host: str, password: str, logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, "", logger, verify_ssl, timeout)

        self._url_firmware = 'admin/firmware?form=upgrade'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client'
        self._url_openvpn = 'admin/openvpn?form=config'
        self._url_pptpd = 'admin/pptpd?form=config'
        self._url_vpnconn_openvpn = 'admin/vpnconn?form=config'
        self._url_vpnconn_pptpd = 'admin/vpnconn?form=config'

        self._headers_request = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "If-Modified-Since": "0",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.host,
            "Connection": "keep-alive",
            "Referer": "{}/webpages/login.html?v=62c60c5d".format(self.host),
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin"
        }

    def identify(self) -> bool:
        """
        Identify if the router is a RE700X
        """
        url = "{}/cgi-bin/luci/;stok=/locale?form=lang".format(self.host)

        headers = self._headers_request

        data = {
            "operation": "read"
        }

        # Disable SSL verification since the local device may use a self-signed certificate
        response = post(url, headers=headers, data=data, verify=False)
        # response of form {"success":true,"data":{"locale":"en_US","force":false,"rebootTime":195,"model":"RE700X"}}
        try:
            data = response.json()
            model = data['data']['model']
            return model == "RE700X"
        except Exception as e:
            error = ('TplinkRouter - {} - Unknown error for identify! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.debug(error)
            return False

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = post(
            url, data={'operation': 'read'},
            timeout=self.timeout,
            verify=self._verify_ssl,
            headers=self._headers_request
        )
        print(response.text)

        try:
            data = response.json()

            args = data[self._data_block]['password']

            self._pwdNN = args[0]
            self._pwdEE = args[1]

        except Exception as e:
            error = ('TplinkRouter - {} - Unknown error for pwd! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def authorize(self) -> None:
        if not self.identify():
            raise ClientError('This router is not a RE700X!')
        if self._pwdNN == '':
            self._request_pwd()

        response = post(
            '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host),
            data={'operation': 'login', 'password': self.password},
            timeout=self.timeout,
            verify=self._verify_ssl,
            headers=self._headers_request,
        )

        data = response.text
        try:
            data = response.json()

            self._stok = data["data"]['stok']
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

    def _is_valid_response(self, data: dict) -> bool:
        return 'success' in data and data['success']

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')
        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)

        response = post(
            url,
            data=data,
            headers=self._headers_request,
            cookies={'sysauth': self._sysauth},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        if ignore_response:
            return None

        data = response.text
        error = ''
        try:
            data = response.json()
            if self._is_valid_response(data):
                return data.get("data")
            elif ignore_errors:
                return data
        except Exception as e:
            error = ('TplinkRouter - {} - An unknown response - {}; Request {} - Response {}'
                     .format(self.__class__.__name__, e, path, data))
        error = ('TplinkRouter - {} - Response with error; Request {} - Response {}'
                 .format(self.__class__.__name__, path, data)) if not error else error
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def logout(self) -> None:
        if self._logged:
            try:
                res = self.request('admin/system?form=logout', 'operation=write')
                print(res)
            except Exception as e:
                error = ("TplinkRouter - {} - Cannot logout! Error - {}"
                         .format(self.__class__.__name__, e))
                if self._logger:
                    self._logger.debug(error)
                raise ClientException(error)
            finally:
                self._logged = False
                self._stok = ''
                self._sysauth = ''