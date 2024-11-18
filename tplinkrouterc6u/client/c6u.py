from hashlib import md5
from re import search
from json import loads
from requests import post, Response
from macaddress import EUI48
from ipaddress import IPv4Address
from logging import Logger
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device, IPv4Reservation, IPv4DHCPLease, IPv4Status
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.client_abstract import AbstractRouter
from abc import abstractmethod


class TplinkRequest:
    host = ''
    _stok = ''
    timeout = 10
    _logged = False
    _sysauth = None
    _verify_ssl = False
    _logger = None
    _headers_request = {}
    _headers_login = {}
    _data_block = 'data'

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')
        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)

        response = post(
            url,
            data=self._prepare_data(data),
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
            self._logger.debug(error)
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

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)

        # If possible implement RSA encryption of password here.
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
            error = ('TplinkRouter - {} - Unknown error for pwd! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _request_seq(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = post(
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
                self._logger.debug(error)
            raise ClientException(error)

    def _try_login(self) -> Response:
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        crypted_pwd = self._encryption.rsa_encrypt(self.password, self._pwdNN, self._pwdEE)

        body = self._prepare_data(self._get_login_data(crypted_pwd))

        return post(
            url,
            data=body,
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    @staticmethod
    def _get_login_data(crypted_pwd: str) -> str:
        return 'operation=login&password={}&confirm=true'.format(crypted_pwd)

    def _prepare_data(self, data: str) -> dict:
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)
        hash = md5((self.username + self.password).encode()).hexdigest()

        sign = self._encryption.get_signature(int(self._seq) + data_len,
                                              True if self._logged is False else False,
                                              hash, self.nn, self.ee)

        return {'sign': sign, 'data': encrypted_data}

    def _decrypt_response(self, data: dict) -> dict:
        return loads(self._encryption.aes_decrypt(data['data']))


class TplinkBaseRouter(AbstractRouter, TplinkRequest):
    _smart_network = True
    _perf_status = True

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._url_firmware = 'admin/firmware?form=upgrade&operation=read'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation&operation=load'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client&operation=load'
        referer = '{}/webpages/index.html'.format(self.host)
        self._headers_request = {'Referer': referer}
        self._headers_login = {'Referer': referer, 'Content-Type': 'application/x-www-form-urlencoded'}

    @abstractmethod
    def authorize(self) -> bool:
        pass

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        values = {
            Connection.HOST_2G: 'wireless_2g',
            Connection.HOST_5G: 'wireless_5g',
            Connection.HOST_6G: 'wireless_6g',
            Connection.GUEST_2G: 'guest_2g',
            Connection.GUEST_5G: 'guest_5g',
            Connection.GUEST_6G: 'guest_6g',
            Connection.IOT_2G: 'iot_2g',
            Connection.IOT_5G: 'iot_5g',
            Connection.IOT_6G: 'iot_6g',
        }
        value = values.get(wifi)
        path = f"admin/wireless?&form=guest&form={value}"
        data = f"operation=write&{value}_enable={'on' if enable else 'off'}"
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
        data = self.request('admin/status?form=all&operation=read', 'operation=read')

        status = Status()
        status._wan_macaddr = EUI48(data['wan_macaddr']) if 'wan_macaddr' in data else None
        status._lan_macaddr = EUI48(data['lan_macaddr'])
        status._wan_ipv4_addr = IPv4Address(data['wan_ipv4_ipaddr']) if 'wan_ipv4_ipaddr' in data else None
        status._lan_ipv4_addr = IPv4Address(data['lan_ipv4_ipaddr']) if 'lan_ipv4_ipaddr' in data else None
        status._wan_ipv4_gateway = IPv4Address(
            data['wan_ipv4_gateway']) if 'wan_ipv4_gateway' in data else None
        status.wan_ipv4_uptime = data.get('wan_ipv4_uptime')
        status.mem_usage = data.get('mem_usage')
        status.cpu_usage = data.get('cpu_usage')
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

        if (status.mem_usage is None or status.mem_usage is None) and self._perf_status:
            try:
                performance = self.request('admin/status?form=perf&operation=read', 'operation=read')
                status.mem_usage = performance.get('mem_usage')
                status.cpu_usage = performance.get('cpu_usage')
            except BaseException:
                self._perf_status = False

        devices = {}

        def _add_device(conn: Connection, item: dict) -> None:
            devices[item['macaddr']] = Device(conn, get_mac(item.get('macaddr', '00:00:00:00:00:00')),
                                              get_ip(item['ipaddr']),
                                              item['hostname'])

        for item in data.get('access_devices_wired', []):
            type = self._map_wire_type(item.get('wire_type'))
            _add_device(type, item)

        for item in data.get('access_devices_wireless_host', []):
            type = self._map_wire_type(item.get('wire_type'))
            _add_device(type, item)

        for item in data.get('access_devices_wireless_guest', []):
            type = self._map_wire_type(item.get('wire_type'), False)
            _add_device(type, item)

        smart_network = None
        if self._smart_network:
            try:
                smart_network = self.request('admin/smart_network?form=game_accelerator', 'operation=loadDevice')
            except Exception:
                self._smart_network = False

        if smart_network:
            for item in smart_network:
                if item['mac'] not in devices:
                    conn = self._map_wire_type(item.get('deviceTag'), not item.get('isGuest'))
                    devices[item['mac']] = Device(conn, get_mac(item.get('mac', '00:00:00:00:00:00')),
                                                  get_ip(item['ip']), item['deviceName'])
                    if conn.is_iot():
                        if status.iot_clients_total is None:
                            status.iot_clients_total = 0
                        status.iot_clients_total += 1

                devices[item['mac']].down_speed = item.get('downloadSpeed')
                devices[item['mac']].up_speed = item.get('uploadSpeed')
                devices[item['mac']].signal = int(item.get('signal')) if item.get('signal') else None

        for item in self.request('admin/wireless?form=statistics', 'operation=load'):
            if item['mac'] not in devices:
                status.wifi_clients_total += 1
                type = self._map_wire_type(item.get('type'))
                devices[item['mac']] = Device(type, EUI48(item['mac']), IPv4Address('0.0.0.0'),
                                              '')
            devices[item['mac']].packets_sent = item.get('txpkts')
            devices[item['mac']].packets_received = item.get('rxpkts')

        status.devices = list(devices.values())
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_status(self) -> IPv4Status:
        ipv4_status = IPv4Status()
        data = self.request('admin/network?form=status_ipv4&operation=read', 'operation=read')
        ipv4_status._wan_macaddr = EUI48(data['wan_macaddr'])
        ipv4_status._wan_ipv4_ipaddr = IPv4Address(data['wan_ipv4_ipaddr'])
        ipv4_status._wan_ipv4_gateway = IPv4Address(data['wan_ipv4_gateway'])
        ipv4_status.wan_ipv4_conntype = data['wan_ipv4_conntype']
        ipv4_status._wan_ipv4_netmask = IPv4Address(data['wan_ipv4_netmask'])
        ipv4_status._wan_ipv4_pridns = IPv4Address(data['wan_ipv4_pridns'])
        ipv4_status._wan_ipv4_snddns = IPv4Address(data['wan_ipv4_snddns'])
        ipv4_status._lan_macaddr = EUI48(data['lan_macaddr'])
        ipv4_status._lan_ipv4_ipaddr = IPv4Address(data['lan_ipv4_ipaddr'])
        ipv4_status.lan_ipv4_dhcp_enable = self._str2bool(data['lan_ipv4_dhcp_enable'])
        ipv4_status._lan_ipv4_netmask = IPv4Address(data['lan_ipv4_netmask'])
        ipv4_status.remote = self._str2bool(data.get('remote'))

        return ipv4_status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        ipv4_reservations = []
        data = self.request(self._url_ipv4_reservations, 'operation=load')

        for item in data:
            ipv4_reservations.append(
                IPv4Reservation(EUI48(item['mac']), IPv4Address(item['ip']), item['comment'],
                                self._str2bool(item['enable'])))

        return ipv4_reservations

    def get_ipv4_dhcp_leases(self) -> [IPv4DHCPLease]:
        dhcp_leases = []
        data = self.request(self._url_ipv4_dhcp_leases, 'operation=load')

        for item in data:
            dhcp_leases.append(
                IPv4DHCPLease(EUI48(item['macaddr']), IPv4Address(item['ipaddr']), item['name'],
                              item['leasetime']))

        return dhcp_leases

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


class TplinkRouter(TplinkEncryption, TplinkBaseRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._url_firmware = 'admin/firmware?form=upgrade'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client'
