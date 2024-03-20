import base64
import hashlib
import re
import json
import time
import urllib
import requests
import datetime
import macaddress
import ipaddress
from logging import Logger
from tplinkrouterc6u.encryption import EncryptionWrapper, EncryptionWrapperMR
from tplinkrouterc6u.enum import Wifi
from tplinkrouterc6u.dataclass import Firmware, Status, Device, IPv4Reservation, IPv4DHCPLease, IPv4Status
from tplinkrouterc6u.exception import ClientException, ClientError
from abc import ABC, abstractmethod


class AbstractRouter(ABC):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 10) -> None:
        self.username = username
        self.password = password
        self.timeout = timeout
        self._logger = logger
        self.host = host
        if not (self.host.startswith('http://') or self.host.startswith('https://')):
            self.host = "http://{}".format(self.host)
        self._verify_ssl = verify_ssl
        if self._verify_ssl is False:
            requests.packages.urllib3.disable_warnings()

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


class TplinkRequest:
    host = ''
    _stok = ''
    timeout = 10
    _logged = False
    _sysauth = None
    _verify_ssl = False
    _logger = None
    _headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    _data_block = 'data'

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')
        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)

        response = requests.post(
            url,
            data=self._prepare_data(data),
            headers=self._headers,
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
            if 'data' not in data:
                raise Exception("Router didn't respond with JSON")
            data = self._decrypt_response(data)

            if self._is_valid_response(data):
                return data.get(self._data_block)
            elif ignore_errors:
                return data
        except Exception as e:
            error = ('TplinkRouter - {} - An unknown response - {}; Request {} - Response {}'
                     .format(self.__class__.__name__, e, path, data))
        error = ('TplinkRouter - {} - Response with error; Request {} - Response {}'
                 .format(self.__class__.__name__, path, data)) if not error else error
        if self._logger:
            self._logger.error(error)
        raise ClientError(error)

    def _is_valid_response(self, data: dict) -> bool:
        return 'success' in data and data['success'] and self._data_block in data

    def _prepare_data(self, data: str):
        return data

    def _decrypt_response(self, data: dict) -> dict:
        return data


class TplinkEncryption(TplinkRequest):
    username = ''
    password = ''
    nn = ''
    ee = ''
    _seq = ''
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

        if self._seq == '':
            self._request_seq()

        response = self._try_login()

        is_valid_json = False
        try:
            response.json()
            is_valid_json = True
        except:
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
            regex_result = re.search(
                'sysauth=(.*);', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._logged = True

        except Exception as e:
            error = ("TplinkRouter - {} - Cannot authorize! Error - {}; Response - {}"
                     .format(self.__class__.__name__, e, data))
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = requests.post(
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
            error = ('TplinkRouter - {} - Unknown error for pwd! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _request_seq(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = requests.post(
            url,
            params={'operation': 'read'},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()

            self._seq = data[self._data_block]['seq']
            args = data[self._data_block]['key']

            self.nn = args[0]
            self.ee = args[1]

        except Exception as e:
            error = ('TplinkRouter - {} - Unknown error for seq! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _try_login(self) -> requests.Response:
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        crypted_pwd = self._encryption.rsa_encrypt(self.password, self._pwdNN, self._pwdEE)

        body = self._prepare_data(self._get_login_data(crypted_pwd))

        return requests.post(
            url,
            data=body,
            headers=self._headers,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    @staticmethod
    def _get_login_data(crypted_pwd: str) -> str:
        return 'operation=login&password={}&confirm=true'.format(crypted_pwd)

    def _prepare_data(self, data: str) -> dict:
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)
        hash = hashlib.md5((self.username + self.password).encode()).hexdigest()

        sign = self._encryption.get_signature(int(self._seq) + data_len, self._logged == False, hash, self.nn,
                                              self.ee)

        return {'sign': sign, 'data': encrypted_data}

    def _decrypt_response(self, data: dict) -> dict:
        return json.loads(self._encryption.aes_decrypt(data['data']))


class TplinkBaseRouter(AbstractRouter, TplinkRequest):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 10) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._url_firmware = 'admin/firmware?form=upgrade&operation=read'
        self._url_wireless_stats = 'admin/wireless?form=statistics&operation=read'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation&operation=load'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client&operation=load'

    @abstractmethod
    def authorize(self) -> bool:
        pass

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
        data = self.request(self._url_firmware, 'operation=read')
        firmware = Firmware(data.get('hardware_version', ''), data.get('model', ''), data.get('firmware_version', ''))

        return firmware

    def get_status(self) -> Status:

        def _calc_cpu_usage(data: dict) -> float | None:
            cpu_usage = (data.get('cpu_usage', 0) + data.get('cpu1_usage', 0)
                         + data.get('cpu2_usage', 0) + data.get('cpu3_usage', 0))
            return cpu_usage / 4 if cpu_usage != 0 else None

        data = self.request('admin/status?form=all&operation=read', 'operation=read')
        status = Status()
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
        status.guest_2g_enable = self._str2bool(data.get('guest_2g_enable'))
        status.guest_5g_enable = self._str2bool(data.get('guest_5g_enable'))
        status.guest_6g_enable = self._str2bool(data.get('guest_6g_enable'))
        status.iot_2g_enable = self._str2bool(data.get('iot_2g_enable'))
        status.iot_5g_enable = self._str2bool(data.get('iot_5g_enable'))
        status.iot_6g_enable = self._str2bool(data.get('iot_6g_enable'))
        status.wifi_2g_enable = self._str2bool(data.get('wireless_2g_enable'))
        status.wifi_5g_enable = self._str2bool(data.get('wireless_5g_enable'))
        status.wifi_6g_enable = self._str2bool(data.get('wireless_6g_enable'))

        devices = {}

        def _add_device(type: Wifi, item: dict) -> None:
            devices[item['macaddr']] = Device(type, macaddress.EUI48(item['macaddr']),
                                              ipaddress.IPv4Address(item['ipaddr']),
                                              item['hostname'])

        for item in data.get('access_devices_wireless_host', []):
            type = self._map_wire_type(item.get('wire_type'))
            _add_device(type, item)

        for item in data.get('access_devices_wireless_guest', []):
            type = self._map_wire_type(item.get('wire_type'), False)
            _add_device(type, item)

        for item in self.request(self._url_wireless_stats, 'operation=read'):
            if item['mac'] not in devices:
                status.wifi_clients_total += 1
                type = self._map_wire_type(item.get('type'))
                devices[item['mac']] = Device(type, macaddress.EUI48(item['mac']), ipaddress.IPv4Address('0.0.0.0'), '')
            devices[item['mac']].packets_sent = item.get('txpkts')
            devices[item['mac']].packets_received = item.get('rxpkts')

        status.devices = list(devices.values())
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_status(self) -> IPv4Status:
        ipv4_status = IPv4Status()
        data = self.request('admin/network?form=status_ipv4&operation=read', 'operation=read')
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

    @staticmethod
    def _str2bool(v) -> bool | None:
        return str(v).lower() in ("yes", "true", "on") if v is not None else None

    @staticmethod
    def _map_wire_type(data: str | None, host: bool = True) -> Wifi:
        result = Wifi.WIFI_UNKNOWN
        if data is None:
            return result
        if data.startswith('2.4'):
            result = Wifi.WIFI_2G if host else Wifi.WIFI_GUEST_2G
        elif data.startswith('5'):
            result = Wifi.WIFI_5G if host else Wifi.WIFI_GUEST_5G
        elif data.startswith('6'):
            result = Wifi.WIFI_6G if host else Wifi.WIFI_GUEST_6G
        return result


class TplinkRouter(TplinkEncryption, TplinkBaseRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 10) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._url_firmware = 'admin/firmware?form=upgrade'
        self._url_wireless_stats = 'admin/wireless?form=statistics'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client'


class TPLinkDecoClient(TplinkEncryption, AbstractRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 10) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._headers = {'Content-Type': 'application/json'}
        self._data_block = 'result'
        self.devices = []

    def logout(self) -> None:
        self.request('admin/system?form=logout', json.dumps({'operation': 'logout'}), True)
        self._stok = ''
        self._sysauth = ''
        self._logged = False

    def set_wifi(self, wifi: Wifi, enable: bool) -> None:
        en = {'enable': enable}
        if Wifi.WIFI_2G == wifi:
            params = {'band2_4': {'host': en}}
        elif Wifi.WIFI_5G == wifi:
            params = {'band5_1': {'host': en}}
        elif Wifi.WIFI_GUEST_5G == wifi:
            params = {'band5_1': {'guest': en}}
        else:
            params = {'band2_4': {'guest': en}}

        self.request('admin/wireless?form=wlan', json.dumps({'operation': 'write', 'params': params}))

    def reboot(self) -> None:
        if not self.devices:
            self.get_firmware()
        self.request('admin/device?form=system', json.dumps({
            'operation': 'reboot',
            'params': {'mac_list': [{"mac": item['mac']} for item in self.devices]}}))

    def get_firmware(self) -> Firmware:
        self.devices = self.request('admin/device?form=device_list', json.dumps({"operation": "read"})).get(
            'device_list', [])

        for item in self.devices:
            if item.get('role') != 'master' and len(self.devices) != 1:
                continue
            firmware = Firmware(item.get('hardware_ver', ''),
                                item.get('device_model', ''),
                                item.get('software_ver', ''))

        return firmware

    def get_status(self) -> Status:
        data = self.request('admin/network?form=wan_ipv4', json.dumps({'operation': 'read'}))

        status = Status()
        element = self._get_value(data, ['wan', 'ip_info', 'mac'])
        status._wan_macaddr = macaddress.EUI48(element) if element else None
        status._lan_macaddr = macaddress.EUI48(self._get_value(data, ['lan', 'ip_info', 'mac']))
        element = self._get_value(data, ['wan', 'ip_info', 'ip'])
        status._wan_ipv4_addr = ipaddress.IPv4Address(element) if element else None
        element = self._get_value(data, ['lan', 'ip_info', 'ip'])
        status._lan_ipv4_addr = ipaddress.IPv4Address(element) if element else None
        element = self._get_value(data, ['wan', 'ip_info', 'gateway'])
        status._wan_ipv4_gateway = ipaddress.IPv4Address(element) if element else None

        data = self.request('admin/network?form=performance', json.dumps({"operation": "read"}))
        status.mem_usage = data.get('mem_usage')
        status.cpu_usage = data.get('cpu_usage')

        data = self.request('admin/wireless?form=wlan', json.dumps({'operation': 'read'}))
        status.wifi_2g_enable = self._get_value(data, ['band2_4', 'host', 'enable'])
        status.guest_2g_enable = self._get_value(data, ['band2_4', 'guest', 'enable'])
        status.wifi_5g_enable = self._get_value(data, ['band5_1', 'host', 'enable'])
        status.guest_5g_enable = self._get_value(data, ['band5_1', 'guest', 'enable'])

        devices = []
        data = self.request('admin/client?form=client_list', json.dumps(
            {"operation": "read", "params": {"device_mac": "default"}})).get('client_list', [])

        for item in data:
            if not item.get('online'):
                continue
            if item.get('wire_type') == 'wired':
                status.wired_total += 1
                continue
            if item.get('interface') == 'main':
                status.wifi_clients_total += 1
            else:
                status.guest_clients_total += 1
            devices.append(Device(self._map_wire_type(item),
                                  macaddress.EUI48(item['mac']),
                                  ipaddress.IPv4Address(item['ip']),
                                  base64.b64decode(item['name']).decode()))

        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total
        status.devices = devices

        return status

    def get_ipv4_status(self) -> IPv4Status:
        ipv4_status = IPv4Status()
        data = self.request('admin/network?form=wan_ipv4', json.dumps({'operation': 'read'}))
        ipv4_status._wan_macaddr = macaddress.EUI48(self._get_value(data, ['wan', 'ip_info', 'mac']))
        element = self._get_value(data, ['wan', 'ip_info', 'ip'])
        ipv4_status._wan_ipv4_ipaddr = ipaddress.IPv4Address(element) if element else None
        element = self._get_value(data, ['wan', 'ip_info', 'gateway'])
        ipv4_status._wan_ipv4_gateway = ipaddress.IPv4Address(element) if element else None
        ipv4_status.wan_ipv4_conntype = self._get_value(data, ['wan', 'dial_type'])
        element = self._get_value(data, ['wan', 'ip_info', 'mask'])
        ipv4_status._wan_ipv4_netmask = ipaddress.IPv4Address(element) if element else None
        ipv4_status._wan_ipv4_pridns = ipaddress.IPv4Address(self._get_value(data, ['wan', 'ip_info', 'dns1']))
        ipv4_status._wan_ipv4_snddns = ipaddress.IPv4Address(self._get_value(data, ['wan', 'ip_info', 'dns2']))
        ipv4_status._lan_macaddr = macaddress.EUI48(self._get_value(data, ['lan', 'ip_info', 'mac']))
        ipv4_status._lan_ipv4_ipaddr = ipaddress.IPv4Address(self._get_value(data, ['lan', 'ip_info', 'ip']))
        ipv4_status.lan_ipv4_dhcp_enable = False
        ipv4_status._lan_ipv4_netmask = ipaddress.IPv4Address(self._get_value(data, ['lan', 'ip_info', 'mask']))

        return ipv4_status

    @staticmethod
    def _get_value(dictionary: dict, keys: list):
        nested_dict = dictionary

        for key in keys:
            try:
                nested_dict = nested_dict[key]
            except Exception:
                return None
        return nested_dict

    @staticmethod
    def _map_wire_type(data: dict) -> Wifi:
        result = Wifi.WIFI_UNKNOWN
        if data.get('connection_type') == 'band2_4':
            result = Wifi.WIFI_2G if data.get('interface') == 'main' else Wifi.WIFI_GUEST_2G
        elif data.get('connection_type') == 'band5':
            result = Wifi.WIFI_5G if data.get('interface') == 'main' else Wifi.WIFI_GUEST_5G
        return result

    @staticmethod
    def _get_login_data(crypted_pwd: str) -> str:
        data = {
            "params": {"password": crypted_pwd},
            "operation": "login",
        }

        return json.dumps(data)

    def _is_valid_response(self, data: dict) -> bool:
        return 'error_code' in data and data['error_code'] == 0


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


class TPLinkMRClient(AbstractRouter):
    REQUEST_RETRIES = 3

    HEADERS = {
        'Accept': '*/*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
        'Referer': 'http://192.168.1.1/'  # updated on the fly
    }

    HTTP_RET_OK = 0
    HTTP_ERR_CGI_INVALID_ANSI = 71017
    HTTP_ERR_USER_PWD_NOT_CORRECT = 71233
    HTTP_ERR_USER_BAD_REQUEST = 71234

    LAN = 0
    WIFI_2G = 1
    WIFI_5G = 3
    WIFI_GUEST_2G = 2
    WIFI_GUEST_5G = 4

    CLIENT_TYPES = {
        WIFI_2G: Wifi.WIFI_2G,
        WIFI_5G: Wifi.WIFI_5G,
        WIFI_GUEST_2G: Wifi.WIFI_GUEST_2G,
        WIFI_GUEST_5G: Wifi.WIFI_GUEST_5G,
    }

    WIFI_SET = {
        Wifi.WIFI_2G: '1,1,0,0,0,0',
        Wifi.WIFI_5G: '1,2,0,0,0,0',
        Wifi.WIFI_GUEST_2G: '1,1,1,0,0,0',
        Wifi.WIFI_GUEST_5G: '1,2,1,0,0,0',
    }

    class ActItem:
        GET = 1
        SET = 2
        ADD = 3
        DEL = 4
        GL = 5
        GS = 6
        OP = 7
        CGI = 8

        def __init__(self, type: int, oid: str, stack: str = '0,0,0,0,0,0', pstack: str = '0,0,0,0,0,0',
                     attrs: list = []):
            self.type = type
            self.oid = oid
            self.stack = stack
            self.pstack = pstack
            self.attrs = attrs

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 10) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self.req = requests.Session()
        self._token = None
        self._hash = hashlib.md5((self.username + self.password).encode()).hexdigest()
        self._nn = None
        self._ee = None
        self._seq = None

        self._encryption = EncryptionWrapperMR()

    def supports(self) -> bool:
        try:
            self._req_rsa_key()
            return True
        except AssertionError:
            return False

    def authorize(self) -> None:
        '''
        Establishes a login session to the host using provided credentials
        '''
        # hash the password

        # request the RSA public key from the host
        self._nn, self._ee, self._seq = self._req_rsa_key()

        # authenticate
        self._req_login()

        # request TokenID
        self._token = self._req_token()

    def logout(self) -> None:
        '''
        Logs out from the host
        '''
        if self._token is None:
            return

        acts = [
            # 8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n
            self.ActItem(self.ActItem.CGI, '/cgi/logout')
        ]

        response, _ = self.req_act(acts)
        ret_code = self._parse_ret_val(response)

        if ret_code == self.HTTP_RET_OK:
            self._token = None

    def get_firmware(self) -> Firmware:
        acts = [
            self.ActItem(self.ActItem.GET, 'IGD_DEV_INFO', attrs=[
                'hardwareVersion',
                'modelName',
                'softwareVersion'
            ])
        ]
        _, values = self.req_act(acts)

        firmware = Firmware(values.get('hardwareVersion', ''), values.get('modelName', ''),
                            values.get('softwareVersion', ''))

        return firmware

    def get_status(self) -> Status:
        status = Status()
        acts = [
            self.ActItem(self.ActItem.GS, 'LAN_IP_INTF', attrs=['X_TP_MACAddress', 'IPInterfaceIPAddress']),
            self.ActItem(self.ActItem.GS, 'WAN_IP_CONN',
                         attrs=['enable', 'MACAddress', 'externalIPAddress', 'defaultGateway']),
            self.ActItem(self.ActItem.GL, 'LAN_WLAN', attrs=['enable', 'X_TP_Band']),
            self.ActItem(self.ActItem.GL, 'LAN_WLAN_GUESTNET', attrs=['enable', 'name']),
            self.ActItem(self.ActItem.GL, 'LAN_HOST_ENTRY', attrs=[
                'IPAddress',
                'MACAddress',
                'hostName',
                'X_TP_ConnType',
                'active',
            ]),
            self.ActItem(self.ActItem.GS, 'LAN_WLAN_ASSOC_DEV', attrs=[
                'associatedDeviceMACAddress',
                'X_TP_TotalPacketsSent',
                'X_TP_TotalPacketsReceived',
            ]),
        ]
        _, values = self.req_act(acts)

        status._lan_macaddr = macaddress.EUI48(values['0']['X_TP_MACAddress'])
        status._lan_ipv4_addr = ipaddress.IPv4Address(values['0']['IPInterfaceIPAddress'])

        for item in self._to_list(values.get('1')):
            if int(item['enable']) == 0 and values.get('1').__class__ == list:
                continue
            status._wan_macaddr = macaddress.EUI48(item['MACAddress'])
            status._wan_ipv4_addr = ipaddress.IPv4Address(item['externalIPAddress'])
            status._wan_ipv4_gateway = ipaddress.IPv4Address(item['defaultGateway'])

        if values['2'].__class__ != list:
            status.wifi_2g_enable = bool(int(values['2']['enable']))
        else:
            status.wifi_2g_enable = bool(int(values['2'][0]['enable']))
            status.wifi_5g_enable = bool(int(values['2'][1]['enable']))

        if values['3'].__class__ != list:
            status.guest_2g_enable = bool(int(values['3']['enable']))
        else:
            status.guest_2g_enable = bool(int(values['3'][0]['enable']))
            status.guest_5g_enable = bool(int(values['3'][1]['enable']))

        devices = {}
        for val in self._to_list(values.get('4')):
            if int(val['active']) == 0:
                continue
            type = int(val['X_TP_ConnType'])
            if type == self.LAN:
                status.wired_total += 1
                continue
            if type in [self.WIFI_GUEST_2G, self.WIFI_GUEST_5G]:
                status.guest_clients_total += 1
            elif type in [self.WIFI_2G, self.WIFI_5G]:
                status.wifi_clients_total += 1
            else:
                continue
            devices[val['MACAddress']] = Device(self.CLIENT_TYPES[type],
                                                macaddress.EUI48(val['MACAddress']),
                                                ipaddress.IPv4Address(val['IPAddress']),
                                                val['hostName'])

        for val in self._to_list(values.get('5')):
            if val['associatedDeviceMACAddress'] not in devices:
                status.wifi_clients_total += 1
                devices[val['associatedDeviceMACAddress']] = Device(
                    Wifi.WIFI_2G,
                    macaddress.EUI48(val['associatedDeviceMACAddress']),
                    ipaddress.IPv4Address('0.0.0.0'),
                    '')
            devices[val['associatedDeviceMACAddress']].packets_sent = int(val['X_TP_TotalPacketsSent'])
            devices[val['associatedDeviceMACAddress']].packets_received = int(val['X_TP_TotalPacketsReceived'])

        status.devices = list(devices.values())
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        acts = [
            self.ActItem(5, 'LAN_DHCP_STATIC_ADDR', attrs=['enable', 'chaddr', 'yiaddr']),
        ]
        _, values = self.req_act(acts)

        ipv4_reservations = []
        for item in self._to_list(values):
            ipv4_reservations.append(
                IPv4Reservation(
                    macaddress.EUI48(item['chaddr']),
                    ipaddress.IPv4Address(item['yiaddr']),
                    '',
                    bool(int(item['enable']))
                ))

        return ipv4_reservations

    def get_ipv4_dhcp_leases(self) -> [IPv4DHCPLease]:
        acts = [
            self.ActItem(5, 'LAN_HOST_ENTRY', attrs=['IPAddress', 'MACAddress', 'hostName', 'leaseTimeRemaining']),
        ]
        _, values = self.req_act(acts)

        dhcp_leases = []
        for item in self._to_list(values):
            lease_time = item['leaseTimeRemaining']
            dhcp_leases.append(
                IPv4DHCPLease(
                    macaddress.EUI48(item['MACAddress']),
                    ipaddress.IPv4Address(item['IPAddress']),
                    item['hostName'],
                    str(datetime.timedelta(seconds=int(lease_time))) if lease_time.isdigit() else 'Permanent',
                ))

        return dhcp_leases

    def get_ipv4_status(self) -> IPv4Status:
        acts = [
            self.ActItem(self.ActItem.GS, 'LAN_IP_INTF',
                         attrs=['X_TP_MACAddress', 'IPInterfaceIPAddress', 'IPInterfaceSubnetMask']),
            self.ActItem(self.ActItem.GET, 'LAN_HOST_CFG', '1,0,0,0,0,0', attrs=['DHCPServerEnable']),
            self.ActItem(self.ActItem.GS, 'WAN_IP_CONN',
                         attrs=['enable', 'MACAddress', 'externalIPAddress', 'defaultGateway', 'name', 'subnetMask',
                                'DNSServers']),
        ]
        _, values = self.req_act(acts)

        ipv4_status = IPv4Status()
        ipv4_status._lan_macaddr = macaddress.EUI48(values['0']['X_TP_MACAddress'])
        ipv4_status._lan_ipv4_ipaddr = ipaddress.IPv4Address(values['0']['IPInterfaceIPAddress'])
        ipv4_status._lan_ipv4_netmask = ipaddress.IPv4Address(values['0']['IPInterfaceSubnetMask'])
        ipv4_status.lan_ipv4_dhcp_enable = bool(int(values['1']['DHCPServerEnable']))

        for item in self._to_list(values.get('2')):
            if int(item['enable']) == 0 and values.get('2').__class__ == list:
                continue
            ipv4_status._wan_macaddr = macaddress.EUI48(item['MACAddress'])
            ipv4_status._wan_ipv4_ipaddr = ipaddress.IPv4Address(item['externalIPAddress'])
            ipv4_status._wan_ipv4_gateway = ipaddress.IPv4Address(item['defaultGateway'])
            ipv4_status.wan_ipv4_conntype = item['name']
            ipv4_status._wan_ipv4_netmask = ipaddress.IPv4Address(item['subnetMask'])
            dns = item['DNSServers'].split(',')
            ipv4_status._wan_ipv4_pridns = ipaddress.IPv4Address(dns[0])
            ipv4_status._wan_ipv4_snddns = ipaddress.IPv4Address(dns[1])

        return ipv4_status

    def set_wifi(self, wifi: Wifi, enable: bool) -> None:
        acts = [
            self.ActItem(
                self.ActItem.SET,
                'LAN_WLAN' if wifi in [Wifi.WIFI_2G, Wifi.WIFI_5G] else 'LAN_WLAN_MSSIDENTRY',
                self.WIFI_SET[wifi],
                attrs=['enable={}'.format(int(enable))]),
        ]
        self.req_act(acts)

    def send_sms(self, phone_number: str, message: str) -> None:
        acts = [
            self.ActItem(
                self.ActItem.SET, 'LTE_SMS_SENDNEWMSG', attrs=[
                    'index=1',
                    'to={}'.format(phone_number),
                    'textContent={}'.format(message),
                ]),
        ]
        self.req_act(acts)

    def reboot(self) -> None:
        acts = [
            self.ActItem(self.ActItem.OP, 'ACT_REBOOT')
        ]
        self.req_act(acts)

    def req_act(self, acts: list):
        '''
        Requests ACTs via the cgi_gdpr proxy
        '''
        act_types = []
        act_data = []

        for act in acts:
            act_types.append(str(act.type))
            act_data.append('[{}#{}#{}]{},{}\r\n{}\r\n'.format(
                act.oid,
                act.stack,
                act.pstack,
                len(act_types) - 1,  # index, starts at 0
                len(act.attrs),
                '\r\n'.join(act.attrs)
            ))

        data = '&'.join(act_types) + '\r\n' + ''.join(act_data)

        url = self._get_url('cgi_gdpr')
        (code, response) = self._request(url, data_str=data, encrypt=True)

        if code != 200:
            error = 'TplinkRouter - MR -  Response with error; Request {} - Response {}'.format(data, response)
            if self._logger:
                self._logger.error(error)
            raise ClientError(error)

        result = self._merge_response(response)

        return response, result.get('0') if len(result) == 1 and result.get('0') else result

    @staticmethod
    def _to_list(response: dict | list | None) -> list:
        if response is None:
            return []

        return [response] if response.__class__ != list else response

    @staticmethod
    def _merge_response(response: str) -> dict:
        result = {}
        obj = {}
        lines = response.split('\n')
        for l in lines:
            if l.startswith('['):
                regexp = re.search('\[\d,\d,\d,\d,\d,\d\](\d)', l)
                if regexp is not None:
                    obj = {}
                    index = regexp.group(1)
                    item = result.get(index)
                    if item is not None:
                        if item.__class__ != list:
                            result[index] = [item]
                        result[index].append(obj)
                    else:
                        result[index] = obj
                continue
            if '=' in l:
                keyval = l.split('=')
                assert len(keyval) == 2

                obj[keyval[0]] = keyval[1]

        return result if result else []

    def _get_url(self, endpoint: str, params: dict = {}, include_ts: bool = True) -> str:
        # add timestamp param
        if include_ts:
            params['_'] = str(round(time.time() * 1000))

        # format params into a string
        params_arr = []
        for attr, value in params.items():
            params_arr.append('{}={}'.format(attr, value))

        # format url
        return '{}/{}{}{}'.format(
            self.host,
            endpoint,
            '?' if len(params_arr) > 0 else '',
            '&'.join(params_arr)
        )

    def _req_token(self):
        '''
        Requests the TokenID, used for CGI authentication (together with cookies)
            - token is inlined as JS var in the index (/) html page
              e.g.: <script type="text/javascript">var token="086724f57013f16e042e012becf825";</script>

        Return value:
            TokenID string
        '''
        url = self._get_url('')
        (code, response) = self._request(url, method='GET')
        assert code == 200

        result = re.search('var token="(.*)";', response)

        assert result is not None
        assert result.group(1) != ''

        return result.group(1)

    def _req_rsa_key(self):
        '''
        Requests the RSA public key from the host

        Return value:
            ((n, e), seq) tuple
        '''
        url = self._get_url('cgi/getParm')
        (code, response) = self._request(url)
        assert code == 200

        # assert return code
        assert self._parse_ret_val(response) == self.HTTP_RET_OK

        # parse public key
        ee = re.search('var ee="(.*)";', response)
        nn = re.search('var nn="(.*)";', response)
        seq = re.search('var seq="(.*)";', response)

        assert ee and nn and seq
        ee = ee.group(1)
        nn = nn.group(1)
        seq = seq.group(1)
        assert len(ee) == 6
        assert len(nn) == 128
        assert seq.isnumeric()

        return nn, ee, int(seq)

    def _req_login(self) -> None:
        '''
        Authenticates to the host
            - sets the session token after successful login
            - data/signature is passed as a GET parameter, NOT as a raw request data
              (unlike for regular encrypted requests to the /cgi_gdpr endpoint)

        Example session token (set as a cookie):
            {'JSESSIONID': '4d786fede0164d7613411c7b6ec61e'}
        '''
        # encrypt username + password

        sign, data = self._prepare_data(self.username + '\n' + self.password, True)
        assert len(sign) == 256

        data = {
            'data': urllib.parse.quote(data, safe='~()*!.\''),
            'sign': sign,
            'Action': 1,
            'LoginStatus': 0,
            'isMobile': 0
        }

        url = self._get_url('cgi/login', data)
        (code, response) = self._request(url)
        assert code == 200

        # parse and match return code
        ret_code = self._parse_ret_val(response)
        error = ''
        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
            info = re.search('var currAuthTimes=(.*);\nvar currForbidTime=(.*);', response)
            assert info is not None

            error = 'TplinkRouter - MR - Login failed, wrong password. Auth times: {}/5, Forbid time: {}'.format(
                info.group(1), info.group(2))
        elif ret_code == self.HTTP_ERR_USER_BAD_REQUEST:
            error = 'TplinkRouter - MR - Login failed. Generic error code: {}'.format(ret_code)
        elif ret_code != self.HTTP_RET_OK:
            error = 'TplinkRouter - MR - Login failed. Unknown error code: {}'.format(ret_code)

        if error:
            if self._logger:
                self._logger.error(error)
            raise ClientException(error)

    def _request(self, url, method='POST', data_str=None, encrypt=False):
        '''
        Prepares and sends an HTTP request to the host
            - sets up the headers, handles token auth
            - encrypts/decrypts the data, if needed

        Return value:
            (status_code, response_text) tuple
        '''
        headers = self.HEADERS

        # add referer to request headers,
        # otherwise we get 403 Forbidden
        headers['Referer'] = self.host

        # add token to request headers,
        # used for CGI auth (together with JSESSIONID cookie)
        if self._token is not None:
            headers['TokenID'] = self._token

        # encrypt request data if needed (for the /cgi_gdpr endpoint)
        if encrypt:
            sign, data = self._prepare_data(data_str, False)
            data = 'sign={}\r\ndata={}\r\n'.format(sign, data)
        else:
            data = data_str

        retry = 0
        while retry < self.REQUEST_RETRIES:
            # send the request
            if method == 'POST':
                r = self.req.post(url, data=data, headers=headers, timeout=self.timeout, verify=self._verify_ssl)
            elif method == 'GET':
                r = self.req.get(url, data=data, headers=headers, timeout=self.timeout, verify=self._verify_ssl)
            else:
                raise Exception('Unsupported method ' + str(method))

            # sometimes we get 500 here, not sure why... just retry the request
            if r.status_code != 500 and '<title>500 Internal Server Error</title>' not in r.text:
                break

            time.sleep(0.05)
            retry += 1

        # decrypt the response, if needed
        if encrypt and (r.status_code == 200) and (r.text != ''):
            return r.status_code, self._encryption.aes_decrypt(r.text)
        else:
            return r.status_code, r.text

    def _parse_ret_val(self, response_text):
        '''
        Parses $.ret value from the response text

        Return value:
            return code (int)
        '''
        result = re.search('\$\.ret=(.*);', response_text)
        assert result is not None
        assert result.group(1).isnumeric()

        return int(result.group(1))

    def _prepare_data(self, data: str, is_login: bool) -> tuple[str, str]:
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)
        # get encrypted signature
        signature = self._encryption.get_signature(int(self._seq) + data_len, is_login, self._hash, self._nn, self._ee)

        # format expected raw request data
        return signature, encrypted_data


class TplinkRouterProvider:
    @staticmethod
    def get_client(host: str, password: str, username: str = 'admin', logger: Logger = None,
                   verify_ssl: bool = True, timeout: int = 10) -> AbstractRouter | None:
        for client in [TPLinkMRClient, TPLinkDecoClient, TplinkRouter, TplinkC1200Router]:
            router = client(host, password, username, logger, verify_ssl, timeout)
            if router.supports():
                return router

        return None
