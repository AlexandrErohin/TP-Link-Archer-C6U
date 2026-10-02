from re import search
from urllib.parse import urlencode, quote_plus
from requests import post
from logging import Logger

from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import (
    Status,
    Device,
    IPv4DHCPLease,
    IPv4Status,
    Firmware,
    WifiStatus,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError


class TplinkRE813XERouter(AbstractRouter):
    """
    TP-Link LuCI Wi-Fi extenders/APs in access-point mode (RE813XE, RE700X, …).

    ``supports()`` does not key off the marketing model name. It detects this
    firmware family by capability: web-encrypted password login works,
    ``admin/status?form=ap_status`` returns wireless AP data, and the full-router
    combined endpoint ``admin/status?form=all`` does not (missing ``Apcfg``).

    RE813XE-oriented host Wi-Fi writes use ``disabled_all`` (packet-captured).
    RE700X-style guest status uses ``admin/status?form=guest`` and
    ``admin/extend?form=guest_settings`` when present; missing endpoints are
    ignored so one client covers both firmwares.
    """

    def __init__(
        self,
        host: str,
        password: str,
        username: str = 'admin',
        logger: Logger = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._stok = ''
        self._sysauth = ''
        self._logged = False
        self._url_firmware = 'admin/firmware?form=upgrade'
        # Matches a real browser session's headers exactly (captured via
        # packet sniffing), for every authenticated request. The Referer used
        # before login is different (see _headers_login) - the real UI's login
        # page and its post-login pages are different URLs.
        common_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': self.host,
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
                           '(KHTML, like Gecko) Version/27.0 Safari/605.1.15'),
            'X-Requested-With': 'XMLHttpRequest',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        }
        self._headers_login = dict(common_headers, Referer='{}/webpages/login.html'.format(self.host))
        self._headers_request = dict(common_headers, Referer='{}/webpages/index.html'.format(self.host))
        # Not confirmed to exist on this device's firmware - no trace of a CPU/
        # memory endpoint in its own web UI or JS. Try once; if it's genuinely
        # unsupported, stop asking rather than hitting it every poll cycle.
        self._perf_status = True

    @staticmethod
    def _str2bool(v) -> bool | None:
        return str(v).lower() in ('yes', 'true', 'on') if v is not None else None

    @staticmethod
    def _map_wire_type(data: str | None, host: bool = True) -> Connection:
        if data is None:
            return Connection.UNKNOWN
        if data == 'wired':
            return Connection.WIRED
        if data.startswith('2.4'):
            return Connection.HOST_2G if host else Connection.GUEST_2G
        if data.startswith('5'):
            return Connection.HOST_5G if host else Connection.GUEST_5G
        if data.startswith('6'):
            return Connection.HOST_6G if host else Connection.GUEST_6G
        if data.startswith('iot_2'):
            return Connection.IOT_2G
        if data.startswith('iot_5'):
            return Connection.IOT_5G
        if data.startswith('iot_6'):
            return Connection.IOT_6G
        return Connection.UNKNOWN

    def _request_optional(self, path: str, data: str = 'operation=read'):
        try:
            return self.request(path, data)
        except ClientError:
            return None

    @staticmethod
    def _device_from_item(conn: Connection, item: dict) -> Device:
        device = Device(
            conn,
            get_mac(item.get('mac', '00-00-00-00-00-00')),
            get_ip(item.get('ipaddr', item.get('ip', ''))),
            item.get('name', ''),
        )
        device.down_speed = item.get('rxrate', item.get('rx_rate'))
        device.up_speed = item.get('txrate', item.get('tx_rate'))
        return device

    def get_firmware(self) -> Firmware:
        data = self.request(self._url_firmware, 'operation=read')
        return Firmware(
            data.get('hardware_version', ''),
            data.get('model', ''),
            data.get('firmware_version', ''),
        )

    def supports(self) -> bool:
        """Detect LuCI AP/extender firmware that lacks full-router status?form=all."""
        if len(self.password) < 200:
            return False

        try:
            self.authorize()
            ap_status = self.request('admin/status?form=ap_status', 'operation=read')
            if not isinstance(ap_status, dict):
                raise ClientException('ap_status response is not a dict')
            ap_markers = (
                'wireless_2g_enable',
                'wireless_5g_enable',
                'wireless_6g_enable',
                'wirelessGrid',
            )
            if not any(key in ap_status for key in ap_markers):
                raise ClientException('ap_status lacks wireless AP fields')

            try:
                self.request('admin/status?form=all', 'operation=read')
            except ClientError:
                # ap_status works and form=all does not → this firmware family.
                # Keep the session; provider returns this same instance.
                return True

            # form=all works → full router (e.g. C5400X); leave for that client.
            self.logout()
            return False
        except Exception as e:
            error = 'TplinkRouter - {} - identify failed! Error - {}'.format(
                self.__class__.__name__, e)
            if self._logger:
                self._logger.debug(error)
            try:
                self.logout()
            except Exception:
                pass
            return False

    def authorize(self) -> None:
        if len(self.password) < 200:
            raise ClientException(
                'You need to use web encrypted password instead. Check the documentation!')

        response = post(
            '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host),
            data='operation=login&password={}'.format(self.password),
            timeout=self.timeout,
            verify=self._verify_ssl,
            headers=self._headers_login,
        )

        text = response.text
        try:
            data = response.json()
            self._stok = data['data']['stok']
            regex_result = search(r'sysauth=([^;]+)', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._logged = True
        except Exception as e:
            error = 'TplinkRouter - {} - Cannot authorize! Error - {}; Response - {}'.format(
                self.__class__.__name__, e, text)
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _is_valid_response(self, data: dict) -> bool:
        return 'success' in data and data['success']

    def request(self, path: str, data: str, ignore_response: bool = False,
                ignore_errors: bool = False) -> dict | list | None:
        if self._logged is False:
            raise ClientException('Not authorised')

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

        text = response.text
        error = ''
        try:
            resp = response.json()
            if self._is_valid_response(resp):
                return resp.get('data')
            elif ignore_errors:
                return resp.get('data', resp)
        except Exception as e:
            error = 'TplinkRouter - {} - An unknown response - {}; Request {} - Response {}'.format(
                self.__class__.__name__, e, path, text)
        error = error or 'TplinkRouter - {} - Response with error; Request {} - Response {}'.format(
            self.__class__.__name__, path, text)
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def logout(self) -> None:
        if self._logged:
            try:
                self.request('admin/system?form=logout', 'operation=write', ignore_response=True)
            except Exception as e:
                error = 'TplinkRouter - {} - Cannot logout! Error - {}'.format(self.__class__.__name__, e)
                if self._logger:
                    self._logger.debug(error)
            finally:
                self._logged = False
                self._stok = ''
                self._sysauth = ''

    def get_status(self) -> Status:
        ap_status = self.request('admin/status?form=ap_status', 'operation=read') or {}
        lan_ipv4 = self._request_optional('admin/network?form=lan_ipv4') or {}
        status_device = self._request_optional('admin/status?form=status_device') or {}
        guest_status = self._request_optional('admin/status?form=guest') or []
        guest_settings = self._request_optional('admin/extend?form=guest_settings') or {}

        status = Status()
        if lan_ipv4.get('lan_macaddr'):
            status._lan_macaddr = get_mac(lan_ipv4['lan_macaddr'])
        if lan_ipv4.get('lan_ip'):
            status._lan_ipv4_addr = get_ip(lan_ipv4['lan_ip'])
        elif status_device.get('wired_ip'):
            # RE700X (and similar) expose the AP LAN address here instead of lan_ipv4.
            status._lan_ipv4_addr = get_ip(status_device['wired_ip'])
            status._wan_ipv4_addr = status._lan_ipv4_addr

        status.wifi_2g_enable = self._str2bool(ap_status.get('wireless_2g_enable'))
        status.wifi_5g_enable = self._str2bool(ap_status.get('wireless_5g_enable'))
        status.wifi_6g_enable = self._str2bool(ap_status.get('wireless_6g_enable'))
        if isinstance(guest_settings, dict):
            status.guest_2g_enable = self._str2bool(guest_settings.get('enable_2g'))
            status.guest_5g_enable = self._str2bool(guest_settings.get('enable_5g'))
            status.guest_6g_enable = self._str2bool(guest_settings.get('enable_6g'))

        devices_by_mac: dict[str, Device] = {}
        for item in ap_status.get('wirelessGrid', []) or []:
            if not isinstance(item, dict):
                continue
            mac = item.get('mac', '00-00-00-00-00-00')
            devices_by_mac[mac] = self._device_from_item(self._map_wire_type(item.get('type')), item)

        if isinstance(guest_status, list):
            status.guest_clients_total = len(guest_status)
            for item in guest_status:
                if not isinstance(item, dict):
                    continue
                mac = item.get('mac', '00-00-00-00-00-00')
                devices_by_mac[mac] = self._device_from_item(
                    self._map_wire_type(item.get('type'), host=False), item)

        status.devices = list(devices_by_mac.values())
        status.wifi_clients_total = ap_status.get('wirelessCount', len(status.devices))
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        if self._perf_status:
            try:
                performance = self.request('admin/status?form=perf', 'operation=read')
                status.mem_usage = performance.get('mem_usage')
                status.cpu_usage = performance.get('cpu_usage')
            except Exception:
                # Not implemented on this firmware (no such page in its own web
                # UI) - stop asking rather than failing every poll cycle.
                self._perf_status = False

        return status

    def get_ipv4_reservations(self) -> list:
        # Access point/extender - DHCP is handled upstream.
        return []

    def get_ipv4_dhcp_leases(self) -> list[IPv4DHCPLease]:
        # Endpoint exists on some firmwares (RE700X returns a list); others return {}.
        data = self.request('admin/dhcps?form=client', 'operation=load') or {}
        leases = []
        if isinstance(data, dict):
            clients = data.values()
        elif isinstance(data, list):
            clients = data
        else:
            clients = []
        for client in clients:
            if not isinstance(client, dict):
                continue
            leases.append(IPv4DHCPLease(
                get_mac(client.get('macaddr', '00:00:00:00:00:00')),
                get_ip(client.get('ipaddr')),
                client.get('name', ''),
                client.get('leasetime', ''),
            ))
        return leases

    def reboot(self) -> None:
        self.request('admin/system?form=reboot', 'operation=write', ignore_response=True)

    _WIFI_FORMS = {
        Connection.HOST_2G: 'wireless_2g',
        Connection.HOST_5G: 'wireless_5g',
        Connection.HOST_6G: 'wireless_6g',
    }

    _GUEST_ENABLE_KEYS = {
        Connection.GUEST_2G: 'enable_2g',
        Connection.GUEST_5G: 'enable_5g',
        Connection.GUEST_6G: 'enable_6g',
    }

    _GUEST_SSID_KEYS = {
        Connection.GUEST_2G: 'ssid_2g',
        Connection.GUEST_5G: 'ssid_5g',
        Connection.GUEST_6G: 'ssid_6g',
    }

    def set_wifi(self, wifi: Connection, enable: bool = None, ssid: str = None, hidden: str = None,
                 encryption: str = None, psk_version: str = None, psk_cipher: str = None, psk_key: str = None,
                 hwmode: str = None, htmode: str = None, channel: int = None, txpower: str = None,
                 disabled_all: str = None, portal_password: str = None) -> None:
        if wifi in self._GUEST_ENABLE_KEYS:
            self._set_guest_wifi(wifi, enable=enable, ssid=ssid, hidden=hidden, psk_key=psk_key)
            return

        value = self._WIFI_FORMS.get(wifi)
        if not value:
            raise ValueError(f'Invalid or unsupported Wi-Fi connection type for RE extender: {wifi}')

        if all(v is None for v in [
                enable, ssid, hidden, encryption, psk_version, psk_cipher, psk_key, hwmode,
                htmode, channel, txpower, disabled_all, portal_password]):
            raise ValueError('At least one wireless setting must be provided')

        # Reverse-engineered from a real packet capture of RE813XE web UI toggles.
        #  1. The real toggle field is 'disabled_all', inverse of 'enable'.
        #  2. Several GET-only fields are never sent by the real UI on write.
        # Disabling only ever sends a minimal field set; enabling sends the full
        # radio config.
        current = self.request(f'admin/wireless?form={value}', 'operation=read') or {}

        def cur(key, override):
            return override if override is not None else current.get(key)

        turning_on = enable if enable is not None else self._str2bool(current.get('enable'))
        disabled_all_value = disabled_all if disabled_all is not None else ('off' if turning_on else 'on')

        data = {
            'twt': current.get('twt'),
            'ofdma': current.get('ofdma'),
            'mimo': current.get('mimo'),
            'enable': None if enable is None else ('on' if enable else 'off'),
        }

        if turning_on:
            data.update({
                'ssid': cur('ssid', ssid),
                'hidden': cur('hidden', hidden),
                'encryption': cur('encryption', encryption),
                'psk_version': cur('psk_version', psk_version),
                'psk_key': cur('psk_key', psk_key),
                'hwmode': cur('hwmode', hwmode),
                'htmode': cur('htmode', htmode),
                'channel': cur('channel', channel),
            })
            if wifi == Connection.HOST_6G:
                data['pscEnable'] = current.get('pscEnable', 'on')
            else:
                data['txpower'] = cur('txpower', txpower)
            if portal_password is not None:
                data['portal_password'] = portal_password

        data['disabled_all'] = disabled_all_value
        data = 'operation=write&' + urlencode({k: v for k, v in data.items() if v is not None}, quote_via=quote_plus)
        self.request(f'admin/wireless?form={value}', data)

    def _set_guest_wifi(self, wifi: Connection, enable: bool = None, ssid: str = None,
                        hidden: str = None, psk_key: str = None) -> None:
        if all(v is None for v in [enable, ssid, hidden, psk_key]):
            raise ValueError('At least one guest wireless setting must be provided')

        current = self.request('admin/extend?form=guest_settings', 'operation=read')
        if not isinstance(current, dict):
            raise ClientException('Guest Wi-Fi settings are not available on this firmware')

        enable_key = self._GUEST_ENABLE_KEYS[wifi]
        ssid_key = self._GUEST_SSID_KEYS[wifi]
        hide_key = enable_key.replace('enable_', 'hide_')

        payload = dict(current)
        if enable is not None:
            payload[enable_key] = 'on' if enable else 'off'
        if ssid is not None:
            payload[ssid_key] = ssid
        if hidden is not None:
            payload[hide_key] = hidden if hidden in ('on', 'off') else ('on' if hidden else 'off')
        if psk_key is not None:
            payload['password'] = psk_key

        data = 'operation=write&' + urlencode(
            {k: v for k, v in payload.items() if v is not None}, quote_via=quote_plus)
        self.request('admin/extend?form=guest_settings', data)

    def get_wifi(self, wifi: Connection) -> WifiStatus:
        if wifi in self._GUEST_ENABLE_KEYS:
            data = self.request('admin/extend?form=guest_settings', 'operation=read')
            if not isinstance(data, dict):
                raise ClientException('Guest Wi-Fi settings are not available on this firmware')
            status = WifiStatus()
            status.enable = self._str2bool(data.get(self._GUEST_ENABLE_KEYS[wifi]))
            status.ssid = data.get(self._GUEST_SSID_KEYS[wifi])
            hide_key = self._GUEST_ENABLE_KEYS[wifi].replace('enable_', 'hide_')
            status.hidden = self._str2bool(data.get(hide_key))
            status.encryption = data.get('sec')
            status.psk_key = data.get('password')
            return status

        value = self._WIFI_FORMS.get(wifi)
        if not value:
            raise ValueError(f'Invalid or unsupported Wi-Fi connection type for RE extender: {wifi}')

        data = self.request(f'admin/wireless?form={value}', 'operation=read')
        status = WifiStatus()
        status.enable = self._str2bool(data.get('enable'))
        status.ssid = data.get('ssid')
        status.hidden = self._str2bool(data.get('hidden'))
        status.encryption = data.get('encryption')
        status.psk_key = data.get('psk_key')
        status.channel = int(data['channel']) if data.get('channel') else None
        return status

    def get_ipv4_status(self) -> IPv4Status:
        lan_ipv4 = self._request_optional('admin/network?form=lan_ipv4') or {}
        status_device = self._request_optional('admin/status?form=status_device') or {}
        ipv4_status = IPv4Status()
        if lan_ipv4.get('lan_macaddr'):
            ipv4_status._lan_macaddr = get_mac(lan_ipv4['lan_macaddr'])
        if lan_ipv4.get('lan_ip'):
            ipv4_status._lan_ipv4_ipaddr = get_ip(lan_ipv4['lan_ip'])
        elif status_device.get('wired_ip'):
            ipv4_status._lan_ipv4_ipaddr = get_ip(status_device['wired_ip'])
        if lan_ipv4.get('lan_netmask'):
            ipv4_status._lan_ipv4_netmask = get_ip(lan_ipv4['lan_netmask'])
        return ipv4_status


# Alias for callers / docs that follow the RE700X naming from #95.
TplinkRe700XRouter = TplinkRE813XERouter
