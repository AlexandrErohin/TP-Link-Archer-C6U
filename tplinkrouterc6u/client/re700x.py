from re import search
from typing import List
from requests import post
from logging import Logger

from tplinkrouterc6u.client_abstract import AbstractRouter, IPv4Status
from tplinkrouterc6u.client.c6u import TplinkRouter, TplinkRequest
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection, VPN
from tplinkrouterc6u.common.dataclass import (
    Status,
    Device,
    IPv4DHCPLease, Firmware,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError


class TplinkRe700XRouter(AbstractRouter, TplinkRequest):
    def __init__(self, host: str, password: str, logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, "", logger, verify_ssl, timeout)

        referer = '{}/webpages/index.html'.format(self.host)
        self._headers_request = {'Referer': referer}
        self._headers_login = {'Referer': referer, 'Content-Type': 'application/x-www-form-urlencoded'}
        self._url_firmware = "admin/firmware?form=upgrade"
        self._headers_request = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "If-Modified-Since": "0",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.host,
            "Connection": "keep-alive",
            "Referer": "{}/webpages/login.html?v=12c60c5d".format(self.host),
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin"
        }

    @staticmethod
    def _str2bool(v) -> bool | None:
        return str(v).lower() in ("yes", "true", "on") if v is not None else None

    @staticmethod
    def _map_wire_type(data: str | None, host: bool = True) -> Connection:
        result = Connection.UNKNOWN
        if data is None:
            return result
        if data == 'wired':
            result = Connection.WIRED
        if data.startswith('2.4'):
            result = Connection.HOST_2G if host else Connection.GUEST_2G
        elif data.startswith('5'):
            result = Connection.HOST_5G if host else Connection.GUEST_5G
        elif data.startswith('6'):
            result = Connection.HOST_6G if host else Connection.GUEST_6G
        elif data.startswith('iot_2'):
            result = Connection.IOT_2G
        elif data.startswith('iot_5'):
            result = Connection.IOT_5G
        elif data.startswith('iot_6'):
            result = Connection.IOT_6G
        return result

    def get_firmware(self) -> Firmware:
        data = self.request(self._url_firmware, 'operation=read')
        firmware = Firmware(data.get('hardware_version', ''), data.get('model', ''), data.get('firmware_version', ''))

        return firmware

    def supports(self) -> bool:
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


    def authorize(self) -> None:

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


    def get_status(self) -> Status:
        status_device = self.request('admin/status?form=status_device', 'operation=read')
        # example answer
        # {"success":true,"data":{"wired_dhcp":"1","wired_ip":"192.168.1.4","wired_type":"0"}}
        ap_status = self.request('admin/status?form=ap_status', 'operation=read', ignore_errors=True)
        # example answer
        """
        {
  "success": true,
  "data": {
    "wireless_2g_encryption": true,
    "show2gFlag": true,
    "phyconn": "connected",
    "wireless_5g_enable": "on",
    "internet_status": "connected",
    "wireless_2g_enable": "on",
    "wireless_5g_encryption": true,
    "opMode": "0",
    "show5gFlag": true,
    "wirelessCount": 8,
    "wirelessGrid": [
      {
        "mac": "7C-2C-67-D9-E9-14",
        "type": "2.4GHz",
        "name": "esp32c3-D9E914",
        "conn_type": "wireless",
        "rxrate": 108,
        "txrate": 150,
        "ipaddr": "192.168.1.52",
        "ip": "192.168.1.52"
      },
      {
        "mac": "26-96-9F-67-1E-C5",
        "type": "5GHz",
        "name": "Mac",
        "conn_type": "wireless",
        "rxrate": 648,
        "txrate": 960,
        "ipaddr": "192.168.1.55",
        "ip": "192.168.1.55"
      },
    ]
  }
    }"""
        guest_status = self.request('admin/status?form=guest', "operation=read", ignore_response=True) or []
        # example answer
        """
        {
  "success": true,
  "data": [
    {
      "mac": "B0-4A-39-98-20-AD",
      "type": "2.4GHz",
      "name": "roborock-vacuum-a51",
      "conn_type": "wireless",
      "rxrate": 150,
      "txrate": 150,
      "ipaddr": "192.168.1.51",
      "ip": "192.168.1.51"
    },
    {
      "mac": "FC-3C-D7-2A-DE-10",
      "type": "2.4GHz",
      "name": "wlan0",
      "conn_type": "wireless",
      "rxrate": 52,
      "txrate": 65,
      "ipaddr": "192.168.1.54",
      "ip": "192.168.1.54"
    }
  ]
}"""
        guest_settings = self.request('admin/extend?form=guest_settings', 'operation=read', ignore_errors=True)
        # example answer
        """{"success":true,"data":{"enable_5g":"off","region_status":1,"hide_5g":"off","hide_2g":"off","show2gFlag":"true","mesh_enable":"off","password":"****","show5gFlag":"true","ap_support_mesh":"0","sync_status":"0","ssid_2g":"****","sec":"wpa2/wpa3","ssid_5g":"****","enable_2g":"on"}}"""

        status = Status()
        status._wan_ipv4_addr = get_ip(status_device.get('wired_ip'))
        status.wifi_clients_total = ap_status.get('wirelessCount')
        status.guest_clients_total = len(guest_status)
        status.guest_2g_enable = self._str2bool(guest_settings.get('enable_2g'))
        status.guest_5g_enable = self._str2bool(guest_settings.get("enable_5g"))
        status.wifi_2g_enable = self._str2bool(ap_status.get('wireless_2g_enable'))
        status.wifi_5g_enable = self._str2bool(ap_status.get('wireless_5g_enable'))

        devices = {}

        def _add_device(conn: Connection, item: dict) -> None:
            devices[item['mac']] = Device(
                conn,
                get_mac(item.get('mac', '00-00-00-00-00-00').replace('-', ':')),
                get_ip(item['ipaddr']),
                item['name'],
                down_speed=item['rxrate'],
                up_speed=item['txrate'],
            )

        for item in ap_status.get('wirelessGrid', []):
            type = self._map_wire_type(item.get('type'))
            _add_device(type, item)

        for item in guest_status:
            type = self._map_wire_type(item.get('type'), False)
            _add_device(type, item)

        status.devices = list(devices.values())
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_reservations(self):
        # No such thing
        return []

    def get_ipv4_dhcp_leases(self) -> List[IPv4DHCPLease]:
        data = self.request("admin/dhcps?form=client", 'operation=load')
        # example answer
        """
        {"success":true,"data":[{"leasetime":"00:00:38","key":"0","macaddr":"a8:46:74:46:14:f8","ipaddr":"192.168.1.59","name":"bedroom-ble"}]}
        """
        leases = []
        for client in data:
            leases.append(IPv4DHCPLease(
                get_mac(client.get('macaddr', '00:00:00:00:00:00')),
                get_ip(client.get('ipaddr')),
                client.get('name', ''),
                client.get('leasetime', ''),
            ))
        return leases

    def reboot(self):
        raise NotImplementedError()

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        raise NotImplementedError()

    def get_ipv4_status(self) -> IPv4Status:
        raise NotImplementedError()
