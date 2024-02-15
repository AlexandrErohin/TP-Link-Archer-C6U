import hashlib
import re
import json
import time
import requests
import macaddress
import ipaddress
from logging import Logger
from tplinkrouterc6u.encryption import EncryptionWrapper
from tplinkrouterc6u.enum import Wifi
from tplinkrouterc6u.dataclass import Firmware, Status, Device, IPv4Reservation, IPv4DHCPLease, IPv4Status
from tplinkrouterc6u.exception import ClientException
from abc import ABC, abstractmethod


class AbstractRouter(ABC):
    @abstractmethod
    def supports(self) -> bool:
        pass

    @abstractmethod
    def authorize(self) -> None:
        pass

    @abstractmethod
    def logout(self) -> None:
        pass

    @abstractmethod
    def get_firmware(self) -> Firmware:
        pass

    @abstractmethod
    def get_status(self) -> Status:
        pass

    @abstractmethod
    def reboot(self) -> None:
        pass

    @abstractmethod
    def set_wifi(self, wifi: Wifi, enable: bool) -> None:
        pass


class TplinkBaseRouter(AbstractRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 10) -> None:
        self.host = host
        if not (self.host.startswith('http://') or self.host.startswith('https://')):
            self.host = "http://{}".format(self.host)
        self._verify_ssl = verify_ssl
        if self._verify_ssl is False:
            requests.packages.urllib3.disable_warnings()
        self.username = username
        self.password = password
        self.timeout = timeout
        self._logger = logger
        self._login_referer = '{}/webpages/login.html?t={}'.format(self.host, time.time())
        self._url_firmware = 'admin/firmware?form=upgrade&operation=read'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation&operation=load'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client&operation=load'

        self._stok = ''
        self._sysauth = ''

        self._logged = False

    @abstractmethod
    def authorize(self) -> bool:
        pass

    def query(self, query, operation='operation=read'):
        self.request(query, operation)

    def set_wifi(self, wifi: Wifi, enable: bool) -> None:
        path = f"admin/wireless?&form=guest&form={wifi.value}"
        data = f"operation=write&{wifi.value}_enable={'on' if enable else 'off'}"
        self.request(path, data)

    def reboot(self) -> None:
        self.request('admin/system?form=reboot', 'operation=write', True)

    def logout(self) -> None:
        self.request('admin/system?form=logout', 'operation=write', True)
        self._stok = ''
        self._sysauth = ''
        self._logged = False

    def get_firmware(self) -> Firmware:
        data = self.request(self._url_firmware)
        firmware = Firmware(data.get('hardware_version', ''), data.get('model', ''), data.get('firmware_version', ''))

        return firmware

    def get_status(self) -> Status:

        def _calc_cpu_usage(data: dict) -> float | None:
            cpu_usage = (data.get('cpu_usage', 0) + data.get('cpu1_usage', 0)
                         + data.get('cpu2_usage', 0) + data.get('cpu3_usage', 0))
            return cpu_usage / 4 if cpu_usage != 0 else None

        data = self.request('admin/status?form=all&operation=read')
        status = Status()
        status.devices = []
        status._wan_macaddr = macaddress.EUI48(data['wan_macaddr']) if 'wan_macaddr' in data else None
        status._lan_macaddr = macaddress.EUI48(data['lan_macaddr'])
        status._wan_ipv4_addr = ipaddress.IPv4Address(data['wan_ipv4_ipaddr']) if 'wan_ipv4_ipaddr' in data else None
        status._lan_ipv4_addr = ipaddress.IPv4Address(data['lan_ipv4_ipaddr']) if 'lan_ipv4_ipaddr' in data else None
        status._wan_ipv4_gateway = ipaddress.IPv4Address(
            data['wan_ipv4_gateway']) if 'wan_ipv4_gateway' in data else None
        status.wan_ipv4_uptime = data.get('wan_ipv4_uptime')
        status.mem_usage = data.get('mem_usage')
        status.cpu_usage = _calc_cpu_usage(data)
        status.wired_total = len(data.get('access_devices_wired', []))
        status.wifi_clients_total = len(data.get('access_devices_wireless_host', []))
        status.guest_clients_total = len(data.get('access_devices_wireless_guest', []))
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total
        status.guest_2g_enable = data.get('guest_2g_enable') == 'on'
        status.guest_5g_enable = data.get('guest_5g_enable') == 'on'
        status.iot_2g_enable = data.get('iot_2g_enable') == 'on' if data.get('iot_2g_enable') is not None else None
        status.iot_5g_enable = data.get('iot_5g_enable') == 'on' if data.get('iot_5g_enable') is not None else None
        status.wifi_2g_enable = data.get('wireless_2g_enable') == 'on'
        status.wifi_5g_enable = data.get('wireless_5g_enable') == 'on'

        for item in data.get('access_devices_wireless_host', []):
            type = Wifi.WIFI_2G if '2.4G' == item['wire_type'] else Wifi.WIFI_5G
            status.devices.append(Device(type, macaddress.EUI48(item['macaddr']), ipaddress.IPv4Address(item['ipaddr']),
                                         item['hostname']))

        for item in data.get('access_devices_wireless_guest', []):
            type = Wifi.WIFI_GUEST_2G if '2.4G' == item['wire_type'] else Wifi.WIFI_GUEST_5G
            status.devices.append(Device(type, macaddress.EUI48(item['macaddr']), ipaddress.IPv4Address(item['ipaddr']),
                                         item['hostname']))

        return status

    def get_ipv4_status(self) -> IPv4Status:
        ipv4_status = IPv4Status()
        data = self.request('admin/network?form=status_ipv4&operation=read')
        ipv4_status._wan_macaddr = macaddress.EUI48(data['wan_macaddr'])
        ipv4_status._wan_ipv4_ipaddr = ipaddress.IPv4Address(data['wan_ipv4_ipaddr'])
        ipv4_status._wan_ipv4_gateway = ipaddress.IPv4Address(data['wan_ipv4_gateway'])
        ipv4_status.wan_ipv4_conntype = data['wan_ipv4_conntype']
        ipv4_status._wan_ipv4_netmask = ipaddress.IPv4Address(data['wan_ipv4_netmask'])
        ipv4_status._wan_ipv4_pridns = ipaddress.IPv4Address(data['wan_ipv4_pridns'])
        ipv4_status._wan_ipv4_snddns = ipaddress.IPv4Address(data['wan_ipv4_snddns'])
        ipv4_status._lan_macaddr = macaddress.EUI48(data['lan_macaddr'])
        ipv4_status._lan_ipv4_ipaddr = ipaddress.IPv4Address(data['lan_ipv4_ipaddr'])
        ipv4_status.lan_ipv4_dhcp_enable = self._str2bool(data['lan_ipv4_dhcp_enable'])
        ipv4_status._lan_ipv4_netmask = ipaddress.IPv4Address(data['lan_ipv4_netmask'])
        ipv4_status.remote = self._str2bool(data.get('remote'))

        return ipv4_status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        ipv4_reservations = []
        data = self.request(self._url_ipv4_reservations, 'operation=load')

        for item in data:
            ipv4_reservations.append(
                IPv4Reservation(macaddress.EUI48(item['mac']), ipaddress.IPv4Address(item['ip']), item['comment'],
                                self._str2bool(item['enable'])))

        return ipv4_reservations

    def get_ipv4_dhcp_leases(self) -> [IPv4DHCPLease]:
        dhcp_leases = []
        data = self.request(self._url_ipv4_dhcp_leases, 'operation=load')

        for item in data:
            dhcp_leases.append(
                IPv4DHCPLease(macaddress.EUI48(item['macaddr']), ipaddress.IPv4Address(item['ipaddr']), item['name'],
                              item['leasetime']))

        return dhcp_leases

    def _str2bool(self, v) -> bool | None:
        return str(v).lower() in ("yes", "true", "on") if v is not None else None

    def request(self, path: str, data: str = 'operation=read', ignore_response: bool = False) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')
        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        referer = '{}/webpages/index.{}.html'.format(self.host, time.time())

        response = requests.post(
            url,
            data=self._prepare_data(data),
            headers={'Referer': referer},
            cookies={'sysauth': self._sysauth},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        if ignore_response:
            return None

        data = response.text
        try:
            data = response.json()
            if 'data' not in data:
                raise Exception("Router didn't respond with JSON")
            data = self._decrypt_response(data)

            if 'success' in data and data['success']:
                return data['data']
        except Exception as e:
            error = 'TplinkRouter - An unknown response - {}; Request {} - Response {}'.format(e, path, data)
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _prepare_data(self, data):
        return data

    def _decrypt_response(self, data):
        return data


class TplinkRouter(TplinkBaseRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 10) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._url_firmware = 'admin/firmware?form=upgrade'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client'

        self._seq = ''
        self._hash = hashlib.md5((self.username + self.password).encode()).hexdigest()

        self.nn = ''
        self.ee = ''

        self._pwdNN = ''
        self._pwdEE = ''

        self._encryption = EncryptionWrapper()

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

        if self._seq == '':
            self._request_seq()

        response = self._try_login()

        if 'text/plain' in response.headers.get('Content-Type'):
            self._request_pwd()
            self._request_seq()
            response = self._try_login()

        data = response.text
        try:
            data = response.json()
            data = self._decrypt_response(data)

            self._stok = data['data']['stok']
            regex_result = re.search(
                'sysauth=(.*);', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._logged = True

        except Exception as e:
            error = "TplinkRouter - C6 - Cannot authorize! Error - {}; Response - {}".format(e, data)
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = requests.post(
            url, params={'operation': 'read'},
            headers={'Referer': self._login_referer},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()

            args = data['data']['password']

            self._pwdNN = args[0]
            self._pwdEE = args[1]

        except Exception as e:
            error = 'TplinkRouter - C6 - Unknown error for pwd! Error - {}; Response - {}'.format(e, response.text)
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _request_seq(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = requests.post(
            url,
            params={'operation': 'read'},
            headers={'Referer': self._login_referer},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()

            self._seq = data['data']['seq']
            args = data['data']['key']

            self.nn = args[0]
            self.ee = args[1]

        except Exception as e:
            error = 'TplinkRouter - C6 - Unknown error for seq! Error - {}; Response - {}'.format(e, response.text)
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _try_login(self) -> requests.Response:
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        cryptedPwd = self._encryption.rsa_encrypt(self.password, self._pwdNN, self._pwdEE)
        data = 'operation=login&password={}&confirm=true'.format(cryptedPwd)

        body = self._prepare_data(data)

        return requests.post(
            url,
            data=body,
            headers={'Referer': self._login_referer, 'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    def _prepare_data(self, data) -> dict:
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)

        sign = self._encryption.get_signature(int(self._seq) + data_len, self._logged == False, self._hash, self.nn,
                                              self.ee)

        return {'sign': sign, 'data': encrypted_data}

    def _decrypt_response(self, data):
        return json.loads(self._encryption.aes_decrypt(data['data']))


class TplinkC1200Router(TplinkBaseRouter):
    def supports(self) -> bool:
        return True

    def authorize(self) -> None:
        if len(self.password) < 200:
            raise Exception('You need to use web encrypted password instead. Check the documentation!')

        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        response = requests.post(
            url,
            params={'operation': 'login', 'username': self.username, 'password': self.password},
            headers={'Referer': self._login_referer, 'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            self._stok = response.json().get('data').get('stok')
            regex_result = re.search('sysauth=(.*);', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._logged = True

        except Exception as e:
            error = "TplinkRouter - C1200 - Cannot authorize! Error - {}; Response - {}".format(e, response.text)
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)


class TplinkRouterProvider:
    @staticmethod
    def get_client(host: str, password: str, username: str = 'admin', logger: Logger = None,
                   verify_ssl: bool = True, timeout: int = 10) -> TplinkRouter | None:
        for client in [TplinkRouter,
                       TplinkC1200Router]:
            router = client(host, password, username, logger, verify_ssl, timeout)
            if router.supports():
                return router

        return None
