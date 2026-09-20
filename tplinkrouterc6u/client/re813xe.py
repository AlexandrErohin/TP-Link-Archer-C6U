from re import search
from typing import List
from urllib.parse import urlencode, quote_plus
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
        # Not confirmed to exist on this device's firmware - no trace of a CPU/
        # memory endpoint in its own web UI or JS. Try once; if it's genuinely
        # unsupported, stop asking rather than hitting it every poll cycle.
        self._perf_status = True

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
        # to remember to. Only the 'operation=xxx' piece itself is duplicated into
        # the URL, not the whole body, to avoid bloating the URL (or leaking
        # sensitive fields like a Wi-Fi password into it) when the body carries
        # more than just that one field.
        if 'operation=' not in path:
            match = search(r'operation=[^&]+', data)
            operation_param = match.group(0) if match else data
            sep = '&' if '?' in path else '?'
            path = '{}{}{}'.format(path, sep, operation_param)

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

        # Reverse-engineered from a real packet capture of this device's own web
        # UI toggling each radio, since blindly echoing the GET response back
        # (an earlier version of this method) turned out to be wrong in two
        # important ways:
        #  1. The real toggle field is 'disabled_all', which is the *inverse* of
        #     'enable' (enable=on pairs with disabled_all=off, and vice versa).
        #     It never appears under that exact name in the GET response (only
        #     as a differently-named, band-prefixed field), so echoing GET data
        #     back never set it correctly - producing a Lua crash ("arithmetic
        #     on a boolean value") observed when only 'enable=on' was sent.
        #  2. Several GET-only fields (psk_cipher, all the wep_* fields) are
        #     never sent by the real UI on write at all.
        # Disabling only ever sends a minimal field set; enabling sends the full
        # radio config. We mirror that here rather than echoing everything back.
        current = self.request(f'admin/wireless?form={value}', 'operation=read') or {}

        def cur(key, override):
            return override if override is not None else current.get(key)

        turning_on = enable if enable is not None else self._str2bool(current.get('enable'))

        data = {
            'twt': current.get('twt'),
            'ofdma': current.get('ofdma'),
            'mimo': current.get('mimo'),
            'enable': None if enable is None else ('on' if enable else 'off'),
            'disabled_all': disabled_all if disabled_all is not None else ('off' if turning_on else 'on'),
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
            # The real UI uses 'txpower' for 2.4/5 GHz and 'pscEnable' for 6 GHz -
            # match whichever this band actually uses, pulled from GET if not
            # explicitly overridden.
            if wifi == Connection.HOST_6G:
                data['pscEnable'] = current.get('pscEnable', 'on')
            else:
                data['txpower'] = cur('txpower', txpower)
            if portal_password is not None:
                data['portal_password'] = portal_password

        data = 'operation=write&' + urlencode({k: v for k, v in data.items() if v is not None}, quote_via=quote_plus)
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
        raise NotImplementedError()       endpoints that otherwise work fine. request() below adds it automatically.
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
        # Not confirmed to exist on this device's firmware - no trace of a CPU/
        # memory endpoint in its own web UI or JS. Try once; if it's genuinely
        # unsupported, stop asking rather than hitting it every poll cycle.
        self._perf_status = True

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
        # to remember to. Only the 'operation=xxx' piece itself is duplicated into
        # the URL, not the whole body, to avoid bloating the URL (or leaking
        # sensitive fields like a Wi-Fi password into it) when the body carries
        # more than just that one field.
        if 'operation=' not in path:
            match = search(r'operation=[^&]+', data)
            operation_param = match.group(0) if match else data
            sep = '&' if '?' in path else '?'
            path = '{}{}{}'.format(path, sep, operation_param)

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

        # This device's Lua backend appears to need the complete set of wireless
        # fields when re-enabling a radio, not just 'enable' on its own - sending
        # only 'enable=on' produced an internal crash ("arithmetic on a boolean
        # value"), while 'enable=off' alone worked fine. Read the current full
        # config and merge our requested changes into it, mirroring what the
        # device's own web UI does when you submit its settings form.
        current = self.request(f'admin/wireless?form={value}', 'operation=read') or {}
        merged = dict(current)

        overrides = {
            'enable': None if enable is None else ('on' if enable else 'off'),
            'ssid': ssid,
            'hidden': hidden,
            'encryption': encryption,
            'psk_version': psk_version,
            'psk_cipher': psk_cipher,
            'psk_key': psk_key,
            'hwmode': hwmode,
            'htmode': htmode,
            'channel': channel,
            'txpower': txpower,
            'disabled_all': disabled_all,
            'portal_password': portal_password,
        }
        for k, v in overrides.items():
            if v is not None:
                merged[k] = v

        data = 'operation=write&' + urlencode(
            {k: v for k, v in merged.items() if v is not None}, quote_via=quote_plus)
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
