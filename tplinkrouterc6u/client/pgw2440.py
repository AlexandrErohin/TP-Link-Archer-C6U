from json import loads
from hashlib import md5
from logging import Logger

from requests import post, Response

from tplinkrouterc6u.client.c6u import TplinkEncryption
from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.dataclass import Device, Firmware, IPv4Status, Status
from tplinkrouterc6u.common.encryption import EncryptionWrapperNoPadding
from tplinkrouterc6u.common.exception import ClientError, ClientException
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


class TplinkPGW2440Router(TplinkEncryption, AbstractRouter):
    """
    TP-Link powerline Wi-Fi extenders with the LuCI-style web API served from
    the web root (PGW2440, …).

    The forms are the LuCI ones (``admin/wireless?form=statistics``, …), but
    they live at ``/<path>``, not under ``/cgi-bin/luci/;stok=``, and the
    session is kept by the device, without a ``stok`` or cookie. Requests use
    the classic ``sign`` / ``data`` encryption with two differences: the
    signature is RSA-encrypted without padding
    (``EncryptionWrapperNoPadding``), and the hash is the MD5 of the password
    alone (the web UI has no user name).

    ``supports()`` only uses forms that need no login, so detecting the device
    never opens a session on it.
    """

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self.host = self.host.rstrip('/')
        self._encryption = EncryptionWrapperNoPadding()
        self._headers_request = {
            'Referer': self.host + '/',
            'Origin': self.host,
            'X-Requested-With': 'XMLHttpRequest',
        }
        self._headers_login = dict(self._headers_request, **{'Content-Type': 'application/x-www-form-urlencoded'})

    def _post(self, path: str, **kwargs) -> Response:
        return post(
            '{}/{}'.format(self.host, path),
            timeout=self.timeout,
            verify=self._verify_ssl,
            **kwargs,
        )

    def _read_plain(self, path: str) -> dict:
        """Read a form the web UI sends without encryption."""
        response = self._post(path, data='operation=read', headers=self._headers_login)
        try:
            data = response.json()
            if not data.get('success'):
                raise ClientError('success is not true')
            return data.get(self._data_block) or {}
        except Exception as e:
            error = ('TplinkRouter - {} - Cannot read {}! Error - {}; Response - {}'
                     .format(self.__class__.__name__, path, e, response.text))
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error) from e

    def supports(self) -> bool:
        if len(self.password) > 125:
            return False
        try:
            keys = self._read_plain('login?form=keys')
            if not keys.get('password'):
                return False
            firmware = self._read_plain('admin/firmware?form=get_firmware_info')
            model = str(firmware.get('model') or '')
            return model.startswith('PGW')
        except Exception:
            return False

    def _request_pwd(self) -> None:
        data = self._read_plain('login?form=keys')
        try:
            self._pwdNN, self._pwdEE = data['password'][0], data['password'][1]
        except Exception as e:
            raise ClientException('TplinkRouter - {} - Unknown error for pwd! Error - {}; Response - {}'
                                  .format(self.__class__.__name__, e, data)) from e

    def _request_seq(self) -> None:
        data = self._read_plain('login?form=auth')
        try:
            self._seq = data['seq']
            self.nn, self.ee = data['key'][0], data['key'][1]
        except Exception as e:
            raise ClientException('TplinkRouter - {} - Unknown error for seq! Error - {}; Response - {}'
                                  .format(self.__class__.__name__, e, data)) from e

    def _prepare_data(self, data: str) -> dict:
        encrypted_data = self._encryption.aes_encrypt(data)
        sign = self._encryption.get_signature(int(self._seq) + len(encrypted_data), self._logged is False,
                                              md5(self.password.encode()).hexdigest(), self.nn, self.ee)
        return {'sign': sign, 'data': encrypted_data}

    def _unwrap(self, response: Response) -> dict:
        """Return the response envelope, decrypting it when it is encrypted.

        Encrypted answers are ``{"data": "<base64>"}``. Plain answers are
        either the envelope itself, or (for some errors, such as an expired
        session) the envelope nested in ``data``.
        """
        data = response.json()
        if isinstance(data.get('data'), str):
            return loads(self._encryption.aes_decrypt(data['data']))
        if 'success' not in data and isinstance(data.get('data'), dict):
            return data['data']
        return data

    def authorize(self) -> None:
        self._logged = False
        self._request_pwd()
        self._request_seq()
        crypted_pwd = self._encryption.rsa_encrypt(self.password, self._pwdNN, self._pwdEE)
        response = self._post(
            'login?form=login',
            data=self._prepare_data('operation=login&password={}&confirm=true'.format(crypted_pwd)),
            headers=self._headers_login,
        )
        try:
            data = self._unwrap(response)
        except Exception as e:
            data = response.text
            error = e
        else:
            error = None if data.get('success') else data.get('errorcode', 'login failed')
        if error is not None:
            message = ('TplinkRouter - {} - Cannot authorize! Error - {}; Response - {}'
                       .format(self.__class__.__name__, error, data))
            if self._logger:
                self._logger.debug(message)
            raise ClientException(message)
        self._logged = True

    def request(self, path: str, data: str, ignore_response: bool = False,
                ignore_errors: bool = False) -> dict | list | None:
        if self._logged is False:
            raise ClientException('Not authorised')

        response = self._post(path, data=self._prepare_data(data), headers=self._headers_login)
        if ignore_response:
            return None

        try:
            envelope = self._unwrap(response)
        except Exception as e:
            error = ('TplinkRouter - {} - An unknown response - {}; Request {} - Response {}'
                     .format(self.__class__.__name__, e, path, response.text))
        else:
            if envelope.get('success'):
                return envelope.get(self._data_block)
            if ignore_errors:
                return envelope
            error = ('TplinkRouter - {} - Response with error; Request {} - Response {}'
                     .format(self.__class__.__name__, path, envelope))
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def logout(self) -> None:
        if self._logged:
            try:
                self.request('logout', 'operation=write', ignore_response=True)
            except Exception as e:
                if self._logger:
                    self._logger.debug('TplinkRouter - {} - Cannot logout! Error - {}'
                                       .format(self.__class__.__name__, e))
            finally:
                self._logged = False

    def get_firmware(self) -> Firmware:
        data = self._read_plain('admin/firmware?form=get_firmware_info')
        return Firmware(data.get('hardware_version', ''), data.get('model', ''), data.get('firmware_version', ''))

    @staticmethod
    def _str2bool(value) -> bool | None:
        return str(value).lower() in ('on', 'yes', 'true', '1') if value is not None else None

    @staticmethod
    def _to_int(value) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _map_wire_type(value) -> Connection:
        value = str(value or '').lower()
        if value.startswith('2'):
            return Connection.HOST_2G
        if value.startswith('5'):
            return Connection.HOST_5G
        if value.startswith('6'):
            return Connection.HOST_6G
        if value in ('wired', 'ethernet', 'lan'):
            return Connection.WIRED
        return Connection.UNKNOWN

    def _read(self, path: str, operation: str = 'read'):
        try:
            return self.request(path, 'operation={}'.format(operation))
        except ClientError:
            return None

    @staticmethod
    def _lan_mac_from_forms(lan: dict, wlan: dict):
        # status_ipv4 has no MAC on this firmware; the 2.4 GHz radio uses the unit's LAN MAC.
        mac = lan.get('lan_macaddr') or wlan.get('wireless_2g_macaddr') or wlan.get('wireless_5g_macaddr')
        return get_mac(mac) if mac else None

    def get_status(self) -> Status:
        lan = self._read('admin/network?form=status_ipv4') or {}
        wlan = self._read('admin/wlan_status') or {}
        clients = self._read('admin/wireless?form=statistics', 'load') or []

        status = Status()
        if lan.get('lan_ipv4_ipaddr'):
            status._lan_ipv4_addr = get_ip(lan['lan_ipv4_ipaddr'])
        status._lan_macaddr = self._lan_mac_from_forms(lan, wlan)
        status.wifi_2g_enable = self._str2bool(wlan.get('wireless_2g_enable'))
        status.wifi_5g_enable = self._str2bool(wlan.get('wireless_5g_enable'))

        devices = []
        for item in clients if isinstance(clients, list) else []:
            if not isinstance(item, dict) or not item.get('mac'):
                continue
            device = Device(self._map_wire_type(item.get('type')), get_mac(item['mac']),
                            get_ip(item.get('ip') or '0.0.0.0'), item.get('devName', ''))
            device.packets_received = self._to_int(item.get('rxpkts'))
            device.packets_sent = self._to_int(item.get('txpkts'))
            devices.append(device)
        status.devices = devices
        status.wifi_clients_total = len(devices)
        status.clients_total = len(devices)
        return status

    def get_ipv4_status(self) -> IPv4Status:
        lan = self._read('admin/network?form=status_ipv4') or {}
        wlan = self._read('admin/wlan_status') or {}
        status = IPv4Status()
        if lan.get('lan_ipv4_ipaddr'):
            status._lan_ipv4_ipaddr = get_ip(lan['lan_ipv4_ipaddr'])
        if lan.get('lan_ipv4_netmask'):
            status._lan_ipv4_netmask = get_ip(lan['lan_ipv4_netmask'])
        status._lan_macaddr = self._lan_mac_from_forms(lan, wlan)
        return status

    def reboot(self) -> None:
        self.request('admin/reboot.json', 'operation=write', ignore_response=True)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        raise NotImplementedError('set_wifi is not implemented for {}'.format(self.__class__.__name__))
