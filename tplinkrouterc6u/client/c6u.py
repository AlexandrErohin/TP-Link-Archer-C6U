from base64 import b64decode, b64encode
from binascii import hexlify
from hashlib import md5, sha256
import hmac
from json import loads
from re import search
import secrets
from urllib.parse import urlencode, quote
from requests import post, Response, get
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from macaddress import EUI48
from ipaddress import IPv4Address
from logging import Logger
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
        self._url_smart_network = 'admin/smart_network?form=game_accelerator&operation=loadDevice'
        self._url_openvpn = 'admin/openvpn?form=config&operation=read'
        self._url_pptpd = 'admin/pptpd?form=config&operation=read'
        self._url_vpnconn_openvpn = 'admin/vpnconn?form=config&operation=list&vpntype=openvpn'
        self._url_vpnconn_pptpd = 'admin/vpnconn?form=config&operation=list&vpntype=pptp'
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
        status._wan_macaddr = EUI48(data['wan_macaddr']) if 'wan_macaddr' in data and data['wan_macaddr'] else None
        status._lan_macaddr = EUI48(data['lan_macaddr'])
        status._wan_ipv4_addr = IPv4Address(data['wan_ipv4_ipaddr']) if 'wan_ipv4_ipaddr' in data else None
        status._lan_ipv4_addr = IPv4Address(data['lan_ipv4_ipaddr']) if 'lan_ipv4_ipaddr' in data else None
        status._wan_ipv4_gateway = IPv4Address(
            data['wan_ipv4_gateway']) if 'wan_ipv4_gateway' in data else None
        status.wan_ipv4_uptime = data.get('wan_ipv4_uptime')
        status.mem_usage = data.get('mem_usage')
        status.cpu_usage = data.get('cpu_usage')
        status.conn_type = data.get('conn_type')
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
                smart_network = self.request(self._url_smart_network, 'operation=loadDevice')
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

        try:
            wireless_stats = self.request('admin/wireless?form=statistics', 'operation=load')
            for item in wireless_stats:
                if item['mac'] not in devices:
                    status.wifi_clients_total += 1
                    type = self._map_wire_type(item.get('type'))
                    devices[item['mac']] = Device(type, EUI48(item['mac']), IPv4Address('0.0.0.0'),
                                                  '')
                devices[item['mac']].packets_sent = item.get('txpkts')
                devices[item['mac']].packets_received = item.get('rxpkts')
        except Exception:
            # WiFi might be disabled on the router, skip wireless statistics
            pass

        status.devices = list(devices.values())
        status.clients_total = (status.wired_total + status.wifi_clients_total + status.guest_clients_total
                                + (status.iot_clients_total or 0))

        return status

    def get_ipv4_status(self) -> IPv4Status:
        ipv4_status = IPv4Status()
        data = self.request('admin/network?form=status_ipv4&operation=read', 'operation=read')
        ipv4_status._wan_macaddr = get_mac(data.get('wan_macaddr', '00:00:00:00:00:00'))
        ipv4_status._wan_ipv4_ipaddr = get_ip(data.get('wan_ipv4_ipaddr', '0.0.0.0'))
        ipv4_status._wan_ipv4_gateway = get_ip(data.get('wan_ipv4_gateway', '0.0.0.0'))
        ipv4_status._wan_ipv4_conntype = data.get('wan_ipv4_conntype', '')
        ipv4_status._wan_ipv4_netmask = get_ip(data.get('wan_ipv4_netmask', '0.0.0.0'))
        ipv4_status._wan_ipv4_pridns = get_ip(data.get('wan_ipv4_pridns', '0.0.0.0'))
        ipv4_status._wan_ipv4_snddns = get_ip(data.get('wan_ipv4_snddns', '0.0.0.0'))
        ipv4_status._lan_macaddr = get_mac(data.get('lan_macaddr', '00:00:00:00:00:00'))
        ipv4_status._lan_ipv4_ipaddr = get_ip(data.get('lan_ipv4_ipaddr', '0.0.0.0'))
        ipv4_status.lan_ipv4_dhcp_enable = self._str2bool(data.get('lan_ipv4_dhcp_enable', ''))
        ipv4_status._lan_ipv4_netmask = get_ip(data.get('lan_ipv4_netmask', '0.0.0.0'))
        ipv4_status.remote = self._str2bool(data.get('remote', '')) if data.get('remote') else None

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

    def get_vpn_status(self) -> VPNStatus:
        status = VPNStatus()

        values = [
            self.request(self._url_openvpn, "operation=read"),
            self.request(self._url_pptpd, "operation=read"),
            self.request(self._url_vpnconn_openvpn, "operation=list&vpntype=openvpn"),
            self.request(self._url_vpnconn_pptpd, "operation=list&vpntype=pptp"),
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
        path = self._url_openvpn if VPN.OPEN_VPN == vpn else self._url_pptpd
        current_config = self.request(path, "operation=read")
        current_config['enabled'] = "on" if enable else "off"
        data = urlencode(current_config)
        data = "operation=write&{}".format(data)
        self.request(path, data)

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
        self._url_smart_network = 'admin/smart_network?form=game_accelerator'
        self._url_openvpn = 'admin/openvpn?form=config'
        self._url_pptpd = 'admin/pptpd?form=config'
        self._url_vpnconn_openvpn = 'admin/vpnconn?form=config'
        self._url_vpnconn_pptpd = 'admin/vpnconn?form=config'


class TplinkRouterSVR(TplinkBaseRouter):
    """Router client for ui-type=svr firmware (BE series)."""

    AES_KEY_LEN = 16
    AES_IV_LEN = 16
    SIGN_CHUNK_LEN = 53

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._url_firmware = 'admin/firmware?form=upgrade'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client'
        self._url_smart_network = 'admin/smart_network?form=game_accelerator'
        self._url_openvpn = 'admin/openvpn?form=config'
        self._url_pptpd = 'admin/pptpd?form=config'
        self._url_vpnconn_openvpn = 'admin/vpnconn?form=config'
        self._url_vpnconn_pptpd = 'admin/vpnconn?form=config'
        self._seq = ''
        self._nn = ''
        self._ee = ''
        self._pwdNN = ''
        self._pwdEE = ''
        self._aes_key = ''
        self._aes_iv = ''
        self._hash = ''
        self._login_username = None

    def supports(self) -> bool:
        try:
            response = get(
                '{}/webpages/index.html'.format(self.host),
                headers={'Accept-Encoding': 'identity'},
                timeout=10,
                verify=self._verify_ssl,
            )
            if response.status_code < 400:
                content = response.text.lower()
                if 'name="ui-type"' in content and 'content="svr"' in content:
                    return True
        except Exception:
            pass

        try:
            response = post(
                '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host),
                data='operation=read',
                headers=self._headers_login,
                timeout=10,
                verify=self._verify_ssl,
            )
            payload = response.json()
            if not payload.get('success'):
                return False
            block = payload.get(self._data_block) or {}
            password_key = block.get('password') or []
            key_len = len(password_key[0]) if isinstance(password_key, list) and password_key else 0
            return block.get('mode') == 'router' and block.get('username') == '' and key_len >= 512
        except Exception:
            return False

    def authorize(self) -> None:
        if not self._seq:
            self._request_seq()
        if not self._pwdNN:
            self._request_pwd()

        self._init_crypto()
        response = self._try_login()
        if response.status_code == 403 or not response.text:
            # Some BE firmware returns empty/403 on stale seq/keys; refresh once.
            self._log_response(response, 'login')
            self._request_seq()
            self._request_pwd()
            self._init_crypto()
            response = self._try_login()

        data = response.text
        try:
            data = response.json()
            data = self._decrypt_response(data)

            if not data.get('success'):
                if self._logger:
                    self._logger.debug('TplinkRouterSVR login failed payload: %s', data)
                error_info = data.get(self._data_block, {})
                error_code = (
                    error_info.get('errorcode')
                    or data.get('errorcode')
                    or data.get('errorCode')
                    or data.get('error_code')
                    or 'unknown error'
                )
                if error_code in {'user conflict', 'multiple login'}:
                    # Confirm=true tells the router to drop the previous session.
                    response = self._try_login(confirm=True)
                    data = response.json()
                    data = self._decrypt_response(data)
                    if data.get('success'):
                        self._stok = data[self._data_block]['stok']
                        if 'set-cookie' in response.headers:
                            match = search(r'sysauth=([^;]+)', response.headers['set-cookie'])
                            if match:
                                self._sysauth = match.group(1)
                        self._logged = True
                        return
                    if self._logger:
                        self._logger.debug(
                            'TplinkRouterSVR login confirm failed payload: %s', data
                        )
                    error_info = data.get(self._data_block, {})
                    error_code = (
                        error_info.get('errorcode')
                        or data.get('errorcode')
                        or data.get('errorCode')
                        or data.get('error_code')
                        or 'unknown error'
                    )
                raise ClientException(
                    'TplinkRouterSVR - {} - Login failed: {}'.format(
                        self.__class__.__name__,
                        error_code,
                    )
                )

            self._stok = data[self._data_block]['stok']
            if 'set-cookie' in response.headers:
                match = search(r'sysauth=([^;]+)', response.headers['set-cookie'])
                if match:
                    self._sysauth = match.group(1)

            self._logged = True

        except ClientException:
            raise
        except Exception as e:
            self._log_response(response, 'login')
            error = (
                'TplinkRouterSVR - {} - Cannot authorize! Error - {}; Response - {}'
                .format(self.__class__.__name__, e, data)
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def logout(self) -> None:
        try:
            self.request('admin/system?form=logout', 'operation=write', True)
        finally:
            self._stok = ''
            self._sysauth = ''
            self._logged = False

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')

        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        encrypted_data = self._aes_encrypt(data)
        response = self._post_encrypted(url, encrypted_data, None)

        if ignore_response:
            return None

        raw = response.text
        error = ''
        try:
            payload = response.json()
            if 'data' not in payload:
                raise Exception("Router didn't respond with JSON")
            payload = self._decrypt_response(payload)

            if self._is_valid_response(payload):
                return payload.get(self._data_block)
            if ignore_errors:
                return payload
        except Exception:
            self._log_response(response, 'request:{}'.format(path))
            # Retry with SHA256(encrypted_body) hash and promote it only on success.
            replaced_hash = sha256(encrypted_data.encode('utf-8')).hexdigest()
            response = self._post_encrypted(url, encrypted_data, replaced_hash)
            raw = response.text
            try:
                payload = response.json()
                if 'data' not in payload:
                    raise Exception("Router didn't respond with JSON")
                payload = self._decrypt_response(payload)
                if self._is_valid_response(payload):
                    self._hash = replaced_hash
                    return payload.get(self._data_block)
                if ignore_errors:
                    return payload
            except Exception as retry_err:
                self._log_response(response, 'request:{}:retry'.format(path))
                error = (
                    'TplinkRouterSVR - {} - An unknown response - {}; Request {} -- Response {}'
                    .format(self.__class__.__name__, retry_err, path, raw)
                )

        if not error:
            error = (
                'TplinkRouterSVR - {} - Response with error; Request {} - Response {}'
                .format(self.__class__.__name__, path, raw)
            )
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def _post_encrypted(self, url: str, encrypted_data: str, hash_override: str | None):
        sign = self._build_sign(len(encrypted_data), is_login=False, hash_override=hash_override)
        return post(
            url,
            data={'sign': sign, 'data': encrypted_data},
            headers=self._headers_request,
            cookies={'sysauth': self._sysauth},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    def _request_seq(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)
        response = post(
            url,
            data='operation=read',
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        try:
            payload = response.json()
            block = payload[self._data_block]
            self._seq = str(block['seq'])
            key = block['key']
            self._nn = key[0]
            self._ee = key[1]
        except Exception as e:
            error = (
                'TplinkRouterSVR - {} - Unknown error for seq! Error - {}; Response - {}'
                .format(self.__class__.__name__, e, response.text)
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)
        response = post(
            url,
            data='operation=read',
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        try:
            payload = response.json()
            block = payload[self._data_block]
            password_key = block['password']
            self._pwdNN = password_key[0]
            self._pwdEE = password_key[1]
            self._login_username = block.get('username')
        except Exception as e:
            error = (
                'TplinkRouterSVR - {} - Unknown error for pwd! Error - {}; Response - {}'
                .format(self.__class__.__name__, e, response.text)
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _init_crypto(self) -> None:
        self._aes_key = self._random_digits(self.AES_KEY_LEN)
        self._aes_iv = self._random_digits(self.AES_IV_LEN)
        login_user = self._login_username if self._login_username is not None else self.username
        self._hash = sha256((login_user + self.password).encode()).hexdigest()

    def _try_login(self, confirm: bool | None = None):
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)
        encrypted_pwd = self._encrypt_password(self.password)
        payload = self._encode_params(
            {
                'password': encrypted_pwd,
                'operation': 'login',
                'confirm': True if confirm else None,
            }
        )
        encrypted = self._aes_encrypt(payload)
        sign = self._build_sign(len(encrypted), is_login=True)
        return post(
            url,
            data={'sign': sign, 'data': encrypted},
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    def _build_sign(self, data_len: int, is_login: bool, hash_override: str | None = None) -> str:
        seq_value = int(self._seq) + data_len
        hash_value = hash_override if hash_override is not None else self._hash
        if is_login:
            sign_data = 'k={}&i={}&h={}&s={}'.format(
                self._aes_key,
                self._aes_iv,
                hash_value,
                seq_value,
            )
            return self._rsa_encrypt_chunks(sign_data)

        sign_data = 'h={}&s={}'.format(hash_value, seq_value)
        return self._hmac_sign_chunks(sign_data)

    def _rsa_encrypt_chunks(self, data: str) -> str:
        key = RSA.construct((int(self._nn, 16), int(self._ee, 16)))
        cipher = PKCS1_OAEP.new(key)
        result = ''
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + self.SIGN_CHUNK_LEN].encode('utf-8')
            encrypted = cipher.encrypt(chunk)
            result += hexlify(encrypted).decode('utf-8')
            pos += self.SIGN_CHUNK_LEN
        return result

    def _encrypt_password(self, password: str) -> str:
        key = RSA.construct((int(self._pwdNN, 16), int(self._pwdEE, 16)))
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(password.encode('utf-8'))
        hex_value = hexlify(encrypted).decode('utf-8')
        if len(hex_value) < len(self._pwdNN):
            hex_value = hex_value.zfill(len(self._pwdNN))
        return hex_value

    def _hmac_sign_chunks(self, data: str) -> str:
        key = 'k={}&i={}'.format(self._aes_key, self._aes_iv).encode('utf-8')
        result = ''
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + self.SIGN_CHUNK_LEN].encode('utf-8')
            result += hmac.new(key, chunk, sha256).hexdigest()
            pos += self.SIGN_CHUNK_LEN
        return result

    def _aes_encrypt(self, raw: str) -> str:
        cipher = AES.new(self._aes_key.encode('utf-8'), AES.MODE_CBC, self._aes_iv.encode('utf-8'))
        encrypted = cipher.encrypt(pad(raw.encode('utf-8'), AES.block_size))
        return b64encode(encrypted).decode('utf-8')

    def _aes_decrypt(self, data: str) -> str:
        cipher = AES.new(self._aes_key.encode('utf-8'), AES.MODE_CBC, self._aes_iv.encode('utf-8'))
        decrypted = cipher.decrypt(b64decode(data))
        return unpad(decrypted, AES.block_size).decode('utf-8')

    def _decrypt_response(self, payload: dict) -> dict:
        return loads(self._aes_decrypt(payload['data']))

    @staticmethod
    def _random_digits(length: int) -> str:
        return ''.join(secrets.choice('0123456789') for _ in range(length))

    @staticmethod
    def _encode_params(params: dict) -> str:
        safe = "-_.!~*'()"
        parts = []
        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, bool):
                value = 'true' if value else 'false'
            parts.append(
                '{}={}'.format(
                    quote(str(key), safe=safe),
                    quote(str(value), safe=safe),
                )
            )
        return '&'.join(parts)

    def _log_response(self, response, context: str) -> None:
        if not self._logger:
            return
        try:
            text = response.text or ''
            snippet = text[:200]
            self._logger.debug(
                'TplinkRouterSVR %s response status=%s content_type=%s len=%s body=%r',
                context,
                response.status_code,
                response.headers.get('content-type'),
                len(text),
                snippet,
            )
        except Exception:
            self._logger.debug('TplinkRouterSVR %s response logging failed', context)


class TplinkRouterV1_11(TplinkBaseRouter):
    """
    Router client for newer TP-Link firmware (1.11.0+) that uses simplified
    RSA-only authentication without AES encryption wrapper.

    Based on fix from: https://github.com/AlexandrErohin/TP-Link-Archer-C6U/issues/90
    """

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._pwdNN = ''
        self._pwdEE = ''

    def supports(self) -> bool:
        """Check if this client can handle the router (new firmware with RSA-only auth)."""
        if len(self.password) > 125:
            return False

        try:
            self._request_pwd()
            # V1_11 uses 2048-bit RSA = 512 hex chars, older firmware uses 1024-bit = 256 chars
            if len(self._pwdNN) >= 512:
                self.authorize()
                self.logout()
                return True
        except Exception:
            return False

    def _request_pwd(self) -> None:
        """Get RSA public key for password encryption."""
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)

        response = post(
            url,
            params={'operation': 'read'},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()
            self._pwdNN = data[self._data_block]['password'][0]
            self._pwdEE = data[self._data_block]['password'][1]
        except Exception as e:
            error = ('TplinkRouterV1_11 - {} - Failed to get encryption keys! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def authorize(self) -> None:
        """Authorize using simplified RSA-only authentication (no AES encryption)."""
        if self._pwdNN == '':
            self._request_pwd()

        # RSA encrypt password using existing utility
        encrypted_pwd = EncryptionWrapper.rsa_encrypt(self.password, self._pwdNN, self._pwdEE)

        # Simple login - just operation=login&password=<HEX>
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)
        response = post(
            url,
            data='operation=login&password={}'.format(encrypted_pwd),
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()
            if not data.get('success'):
                error_info = data.get(self._data_block, {})
                raise ClientException(
                    'TplinkRouterV1_11 - {} - Login failed: {}'.format(
                        self.__class__.__name__,
                        error_info.get('errorcode', 'unknown error')
                    )
                )

            self._stok = data[self._data_block]['stok']

            # Get sysauth cookie
            if 'set-cookie' in response.headers:
                regex_result = search(r'sysauth=([^;]+)', response.headers['set-cookie'])
                if regex_result:
                    self._sysauth = regex_result.group(1)

            self._logged = True

        except ClientException:
            raise
        except Exception as e:
            error = ('TplinkRouterV1_11 - {} - Cannot authorize! Error - {}; Response - {}'
                     .format(self.__class__.__name__, e, response.text))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)
