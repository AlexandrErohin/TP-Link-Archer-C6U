from re import search
from typing import List
from requests import post
from logging import Logger

from tplinkrouterc6u.client_abstract import AbstractRouter, IPv4Status
from tplinkrouterc6u.client.c6u import TplinkRequest
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import (
    Status,
    Device,
    IPv4DHCPLease,
    Firmware,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError


class TplinkRE813XERouter(AbstractRouter, TplinkRequest):
    """
    TP-Link RE813XE (and likely other RE-series Wi-Fi 6E extenders sharing this
    firmware family) operating in access-point/extender mode.

    Two firmware quirks distinguish it from full routers on the same general LuCI
    JSON API family (e.g. TplinkC5400XRouter):

    1. It doesn't implement the combined 'admin/status?form=all' endpoint full
       routers use to fetch everything in one call - its Lua backend raises an
       internal error (missing 'Apcfg' section) because it lacks full-router
       features like a separate access-point config block. Its own web UI instead
       queries several narrower, per-section endpoints (see get_status()).
    2. Its minimal CGI backend requires 'operation=' to be present in the URL
       query string itself, not just the POST body, for a 'form' callback to be
       recognised - omitting it produces a generic
       {"success": false, "errorcode": "no such callback"} response even for
       endpoints that otherwise work fine. request() below adds it automatically.
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

        referer = '{}/webpages/index.html'.format(self.host)
        self._url_firmware = 'admin/firmware?form=upgrade'
        # Keep this minimal and matching exactly what was proven to work against
        # the real device - extra headers (Content-Type, Accept, X-Requested-With,
        # etc.) that other client classes in this library add were tried and
        # caused 'no such callback' errors on this device's minimal CGI backend.
        self._headers_request = {'Referer': referer, 'Origin': self.host}

    @staticmethod
    def _str2bool(v) -> bool | None:
        return str(v).lower() in ('yes', 'true', 'on') if v is not None else None

    @staticmethod
    def _map_wire_type(data: str | None) -> Connection:
        if data is None:
            return Connection.UNKNOWN
        if data.startswith('2.4'):
            return Connection.HOST_2G
        if data.startswith('5'):
            return Connection.HOST_5G
        if data.startswith('6'):
            return Connection.HOST_6G
        return Connection.UNKNOWN

    def get_firmware(self) -> Firmware:
        data = self.request(self._url_firmware, 'operation=read')
        return Firmware(
            data.get('hardware_version', ''),
            data.get('model', ''),
            data.get('firmware_version', ''),
        )

    def supports(self) -> bool:
        """Identify if the router is a RE813XE."""
        # Consistent with every other endpoint on this device: 'operation=' must be
        # present in the URL query string itself, not just the POST body, or the
        # router intermittently responds with a generic 'no such callback' error
        # (observed even for this specific pre-auth call, despite an earlier real
        # browser capture not having it there - that apparently isn't reliable).
        url = '{}/cgi-bin/luci/;stok=/locale?form=lang&operation=read'.format(self.host)
        response = None
        try:
            response = post(
                url,
                headers=self._headers_request,
                data='operation=read',
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            resp = response.json()
            model = resp.get('data', {}).get('model')
            match = model == 'RE813XE'
            if not match and self._logger:
                self._logger.debug(
                    'TplinkRouter - {} - identify check ran fine but model was {!r}, not RE813XE'.format(
                        self.__class__.__name__, model))
            return match
        except Exception as e:
            error = 'TplinkRouter - {} - Unknown error for identify! Error - {}; Response - {}'.format(
                self.__class__.__name__, e, getattr(response, 'text', '<no response>'))
            if self._logger:
                self._logger.debug(error)
            return False

    def authorize(self) -> None:
        if len(self.password) < 200:
            raise ClientException(
                'You need to use web encrypted password instead. Check the documentation!')

        response = post(
            '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host),
            data={'operation': 'login', 'password': self.password},
            timeout=self.timeout,
            verify=self._verify_ssl,
            headers=self._headers_request,
        )

        text = response.text
        try:
            data = response.json()
            self._stok = data['data']['stok']
            regex_result = search('sysauth=(.*);', response.headers['set-cookie'])
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
                ignore_errors: bool = False) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')

        # This device requires 'operation=' in the URL query string itself, not
        # just the POST body - add it automatically so every caller doesn't need
        # to remember to.
        if 'operation=' not in path:
            sep = '&' if '?' in path else '?'
            path = '{}{}{}'.format(path, sep, data)

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
                return resp
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
        ap_status = self.request('admin/status?form=ap_status', 'operation=read')
        try:
            lan_ipv4 = self.request('admin/network?form=lan_ipv4', 'operation=read')
        except Exception:
            lan_ipv4 = {}

        status = Status()
        status._lan_macaddr = get_mac(lan_ipv4['lan_macaddr']) if lan_ipv4.get('lan_macaddr') else None
        status._lan_ipv4_addr = get_ip(lan_ipv4['lan_ip']) if lan_ipv4.get('lan_ip') else None
        status.wifi_2g_enable = self._str2bool(ap_status.get('wireless_2g_enable'))
        status.wifi_5g_enable = self._str2bool(ap_status.get('wireless_5g_enable'))
        status.wifi_6g_enable = self._str2bool(ap_status.get('wireless_6g_enable'))

        devices = []
        for item in ap_status.get('wirelessGrid', []) or []:
            conn = self._map_wire_type(item.get('type'))
            devices.append(Device(
                conn,
                get_mac(item.get('mac', '00-00-00-00-00-00')),
                get_ip(item.get('ipaddr', item.get('ip', ''))),
                item.get('name', ''),
            ))
        status.devices = devices
        status.wifi_clients_total = ap_status.get('wirelessCount', len(devices))
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_reservations(self):
        # This device acts as an access point/extender - DHCP is handled upstream,
        # there's no reservation concept here.
        return []

    def get_ipv4_dhcp_leases(self) -> List[IPv4DHCPLease]:
        # Same reasoning as get_ipv4_reservations - the endpoint exists but returns
        # an empty object on this device, since DHCP is handled upstream. We still
        # call it (rather than hardcoding []) in case a future firmware or a
        # closely related model actually populates it.
        data = self.request('admin/dhcps?form=client', 'operation=load') or {}
        leases = []
        for client in (data.values() if isinstance(data, dict) else data):
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

    def set_wifi(self, wifi: Connection, enable: bool = None, ssid: str = None, hidden: str = None,
                 encryption: str = None, psk_version: str = None, psk_cipher: str = None, psk_key: str = None,
                 hwmode: str = None, htmode: str = None, channel: int = None, txpower: str = None,
                 disabled_all: str = None, portal_password: str = None) -> None:
        value = self._WIFI_FORMS.get(wifi)
        if not value:
            # This device is a simple AP/extender - it has no guest or IoT
            # networks, only the three host bands above.
            raise ValueError(f"Invalid or unsupported Wi-Fi connection type for RE813XE: {wifi}")

        if all(v is None for v in [enable, ssid, hidden, encryption, psk_version, psk_cipher, psk_key, hwmode,
                                    htmode, channel, txpower, disabled_all, portal_password]):
            raise ValueError("At least one wireless setting must be provided")

        data = 'operation=write'
        # The real device's own get_wifi() response for this endpoint uses plain
        # field names ('enable', 'ssid', ...), not '{band}_enable' - match that
        # on write too rather than the '{value}_...'-prefixed style some other
        # client classes in this codebase use for their own wireless forms.
        if enable is not None:
            data += f"&enable={'on' if enable else 'off'}"
        if ssid is not None:
            data += f"&ssid={ssid}"
        if hidden is not None:
            data += f"&hidden={hidden}"
        if encryption is not None:
            data += f"&encryption={encryption}"
        if psk_version is not None:
            data += f"&psk_version={psk_version}"
        if psk_cipher is not None:
            data += f"&psk_cipher={psk_cipher}"
        if psk_key is not None:
            data += f"&psk_key={psk_key}"
        if hwmode is not None:
            data += f"&hwmode={hwmode}"
        if htmode is not None:
            data += f"&htmode={htmode}"
        if channel is not None:
            data += f"&channel={channel}"
        if txpower is not None:
            data += f"&txpower={txpower}"
        if disabled_all is not None:
            data += f"&disabled_all={disabled_all}"
        if portal_password is not None:
            data += f"&portal_password={portal_password}"

        self.request(f'admin/wireless?form={value}', data)

    def get_wifi(self, wifi: Connection):
        from tplinkrouterc6u.common.dataclass import WifiStatus

        value = self._WIFI_FORMS.get(wifi)
        if not value:
            raise ValueError(f"Invalid or unsupported Wi-Fi connection type for RE813XE: {wifi}")

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
        raise NotImplementedError()
