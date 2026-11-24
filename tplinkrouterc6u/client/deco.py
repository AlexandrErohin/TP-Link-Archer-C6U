# Modified 2026-11-24: verify one Wi-Fi write using bounded WLAN-only reads.
from base64 import b64decode
from dataclasses import dataclass
from json import dumps
from math import isfinite
from time import sleep
from types import MappingProxyType
from urllib.parse import urlsplit
from requests.exceptions import Timeout
from collections.abc import Callable, Mapping
from logging import Logger
from tplinkrouterc6u.common.helper import get_ip, get_mac, get_value
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device, IPv4Status, LTEStatus, MeshNode
from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.client.c6u import TplinkEncryption
from tplinkrouterc6u.client.deco_tmp import DecoTMPTransport, DecoTMPError, DecoTMPRejected
from tplinkrouterc6u.common.exception import (
    ClientException, ClientError, WifiVerificationError, WifiWriteNotObserved,
    WifiVerificationUnavailable, WifiWriteRejected,
)


_WIFI_BANDS = {
    Connection.HOST_2G: ('band2_4', 'host'),
    Connection.GUEST_2G: ('band2_4', 'guest'),
    Connection.HOST_5G: ('band5_1', 'host'),
    Connection.GUEST_5G: ('band5_1', 'guest'),
    Connection.HOST_6G: ('band6', 'host'),
    Connection.GUEST_6G: ('band6', 'guest'),
}


@dataclass(frozen=True)
class WifiWriteResult:
    wifi: Connection
    enable: bool
    states: Mapping[Connection, bool]

    def __post_init__(self) -> None:
        object.__setattr__(self, 'states', MappingProxyType(dict(self.states)))


class TPLinkDecoClient(TplinkEncryption, AbstractRouter):
    # Deco meshes with many clients routinely need >30s for a full get_status()
    # poll when one endpoint (often client_list) is slow; 60s keeps that survivable.
    _DEFAULT_TIMEOUT = 60
    # Total attempts = _RETRY_MAX + 1 (initial try plus this many retries).
    _RETRY_MAX = 2

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = _DEFAULT_TIMEOUT) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._headers_request = {'Content-Type': 'application/json'}
        self._headers_login = {'Content-Type': 'application/json'}
        self._data_block = 'result'
        self._tmp_wifi_options = None

    # supports() stays the cheap TplinkEncryption keys probe. SG-stack Halo units
    # are claimed earlier by TplinkDecoSGRouter in TplinkRouterProvider.get_clients().

    def logout(self) -> None:
        self.request('admin/system?form=logout', dumps({'operation': 'logout'}), True)
        self._reset_session()

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        bands = {
            Connection.HOST_2G: ('band2_4', 'host'),
            Connection.GUEST_2G: ('band2_4', 'guest'),
            Connection.HOST_5G: ('band5_1', 'host'),
            Connection.GUEST_5G: ('band5_1', 'guest'),
            Connection.HOST_6G: ('band6', 'host'),
            Connection.GUEST_6G: ('band6', 'guest'),
        }
        if wifi not in bands:
            # Only host/guest × 2.4/5/6 GHz are mapped; anything else would
            # previously fall through and silently toggle the 2.4 GHz guest network.
            raise ClientException(f'Unsupported wifi connection for Deco set_wifi: {wifi}')
        band, network = bands[wifi]
        params = {band: {network: {'enable': enable}}}

        self.request('admin/wireless?form=wlan', dumps({'operation': 'write', 'params': params}))

    @property
    def supports_verified_wifi(self) -> bool:
        """Whether the one-shot classic Deco transport applies to this client."""
        return type(self)._request_with_reauth is TPLinkDecoClient._request_with_reauth

    def configure_tmp_wifi(self, *, username_sha1: str, host_key_sha256: str) -> None:
        """Opt in to the local app transport using an explicit identity and pin.

        Validation constructs no connection. The existing password is reused;
        the caller must ensure it is also valid for the supplied local account.
        """
        if not self.supports_verified_wifi:
            raise ValueError('The app Wi-Fi transport requires a classic Deco client')
        host = urlsplit(self.host)
        if host.username is not None or host.password is not None or host.hostname is None:
            raise ValueError('A router hostname or IP address is required')
        DecoTMPTransport(host.hostname, username_sha1, self.password, host_key_sha256)
        self._tmp_wifi_options = (host.hostname, username_sha1, host_key_sha256)

    def set_wifi_verified(self, wifi: Connection, enable: bool, attempts: int = 3,
                          poll_interval: float = 1.0) -> WifiWriteResult:
        """Send one minimal write and accept only a subsequent observed state.

        The caller must authorize and serialize access to the router session.
        Neither an unreadable write reply nor a timeout permits a second write.
        Confirmation uses only WLAN reads, including the existing HTTP session
        when an app connection is lost after its one-shot write.
        """
        if not isinstance(wifi, Connection) or wifi not in _WIFI_BANDS:
            raise ValueError('Unsupported Wi-Fi network for Deco verification')
        if type(enable) is not bool:
            raise ValueError('enable must be a bool')
        if type(attempts) is not int or attempts < 1:
            raise ValueError('attempts must be a positive integer')
        if (type(poll_interval) not in (int, float) or not isfinite(poll_interval)
                or poll_interval < 0):
            raise ValueError('poll_interval must be finite and nonnegative')
        # SG/E4R override the encrypted transport. Do not send a classic Deco
        # request on their sessions without a separately verified implementation.
        if not self.supports_verified_wifi:
            raise WifiVerificationUnavailable(error_type='UnsupportedTransport') from None

        if self._tmp_wifi_options and _WIFI_BANDS[wifi][1] == 'guest':
            return self._set_guest_wifi_tmp_verified(wifi, enable, attempts, poll_interval)

        band, network = _WIFI_BANDS[wifi]
        payload = {'operation': 'write', 'params': {band: {network: {'enable': enable}}}}
        write_rejected = False
        error_type = None
        try:
            response = self._wifi_request_once(payload)
            write_rejected = self._wifi_rejected(response)
            if write_rejected:
                error_type = 'RouterRejected'
        except Exception as err:
            # Error text can contain a decrypted response or credentials.
            error_type = type(err).__name__

        latest_states = {}
        target_observed = False
        for attempt in range(attempts):
            if attempt:
                sleep(poll_interval)
            try:
                response = self._wifi_request_once({'operation': 'read'})
                if self._wifi_rejected(response):
                    error_type = 'RouterRejected'
                    continue
                states = self._wifi_states(response)
                latest_states = states
            except Exception as err:
                error_type = type(err).__name__
                continue
            if write_rejected:
                raise WifiWriteRejected(latest_states, error_type) from None
            if wifi in states:
                target_observed = True
                if states[wifi] is enable:
                    return WifiWriteResult(wifi, enable, states)

        if write_rejected:
            raise WifiWriteRejected(latest_states, error_type) from None
        if target_observed:
            raise WifiWriteNotObserved(latest_states, error_type) from None
        raise WifiVerificationUnavailable(latest_states, error_type) from None

    def _set_guest_wifi_tmp_verified(self, wifi: Connection, enable: bool,
                                     attempts: int, poll_interval: float) -> WifiWriteResult:
        """Read first, send at most one app command, then verify observed WLAN.

        An uncertain app write is never replayed through either transport. This
        path is enabled only by configure_tmp_wifi; ordinary HTTP reads and all
        non-guest controls retain their existing behavior.
        """
        host, username, pin = self._tmp_wifi_options
        latest_states = {}
        try:
            with DecoTMPTransport(host, username, self.password, pin) as transport:
                latest_states = self._wifi_states(transport.get_wlan())
                if wifi not in latest_states:
                    raise WifiVerificationUnavailable(error_type='TMPStateUnavailable') from None
                if latest_states[wifi] is enable:
                    return WifiWriteResult(wifi, enable, latest_states)
                rejected = False
                error_type = None
                read_from_tmp = True
                try:
                    transport.set_guest_wifi(wifi, enable)
                except DecoTMPRejected as error:
                    rejected = True
                    error_type = error.error_type
                    read_from_tmp = False
                except Exception as error:
                    error_type = type(error).__name__
                    read_from_tmp = False
                target_observed = False
                for attempt in range(attempts):
                    if attempt:
                        sleep(poll_interval)
                    try:
                        if read_from_tmp:
                            try:
                                response = transport.get_wlan()
                            except DecoTMPError:
                                read_from_tmp = False
                                response = self._wifi_request_once({'operation': 'read'})
                        else:
                            response = self._wifi_request_once({'operation': 'read'})
                        if self._wifi_rejected(response):
                            error_type = 'RouterRejected'
                            continue
                        latest_states = self._wifi_states(response)
                    except Exception as error:
                        error_type = type(error).__name__
                        continue
                    if rejected:
                        raise WifiWriteRejected(latest_states, error_type) from None
                    if wifi in latest_states:
                        target_observed = True
                        if latest_states[wifi] is enable:
                            return WifiWriteResult(wifi, enable, latest_states)
                if rejected:
                    raise WifiWriteRejected(latest_states, error_type) from None
                if target_observed:
                    raise WifiWriteNotObserved(latest_states, error_type) from None
                raise WifiVerificationUnavailable(latest_states, error_type) from None
        except WifiVerificationError:
            raise
        except DecoTMPError as error:
            raise WifiVerificationUnavailable(latest_states, error.error_type) from None
        except Exception as error:
            raise WifiVerificationUnavailable(latest_states, type(error).__name__) from None

    def _wifi_request_once(self, payload: dict) -> dict | None:
        """Bypass Deco automatic retries/reauthorization for this operation.

        ignore_errors preserves a parseable explicit rejection envelope. The
        upstream logger can include raw responses, so silence it during this
        bounded call; callers receive only sanitized verification errors.
        """
        logger = self._logger
        self._logger = None
        try:
            return TplinkEncryption.request(
                self, 'admin/wireless?form=wlan', dumps(payload), ignore_errors=True)
        finally:
            self._logger = logger

    @staticmethod
    def _wifi_rejected(response) -> bool:
        if not isinstance(response, dict):
            return False
        code = response.get('error_code')
        return type(code) is int and code != 0

    @staticmethod
    def _wifi_states(response) -> dict[Connection, bool]:
        if not isinstance(response, dict):
            return {}
        states = {}
        for wifi, (band, network) in _WIFI_BANDS.items():
            band_data = response.get(band)
            if not isinstance(band_data, dict):
                continue
            network_data = band_data.get(network)
            if not isinstance(network_data, dict):
                continue
            value = network_data.get('enable')
            if type(value) is bool:
                states[wifi] = value
            elif type(value) is int and value in (0, 1):
                states[wifi] = value == 1
            elif type(value) is str:
                value = value.lower()
                if value in ('on', 'true'):
                    states[wifi] = True
                elif value in ('off', 'false'):
                    states[wifi] = False
        return states

    def reboot(self) -> None:
        devices = self._fetch_devices()
        self.request('admin/device?form=system', dumps({
            'operation': 'reboot',
            'params': {'mac_list': [{"mac": item['mac']} for item in devices]}}))

    def get_firmware(self) -> Firmware:
        devices = self._fetch_devices()

        for item in devices:
            if item.get('role') != 'master' and len(devices) != 1:
                continue
            firmware = Firmware(item.get('hardware_ver', ''),
                                item.get('device_model', ''),
                                item.get('software_ver', ''))

        return firmware

    def get_mesh_nodes(self) -> list[MeshNode]:
        """Return every unit of the mesh, master included, as the router reports it now."""
        devices = self._fetch_devices()

        nodes = []
        for item in devices:
            signal = item.get('signal_strength') or {}
            rx = item.get('rx_rate_list') or {}
            tx = item.get('tx_rate_list') or {}
            ip = item.get('device_ip')
            parent = item.get('previous')

            nodes.append(MeshNode(
                _macaddr=get_mac(item.get('mac')),
                name=item.get('nickname', ''),
                role=item.get('role', ''),
                # The shared connection state; Deco reports it as group_status, in EasyMesh's vocabulary.
                status=item.get('group_status'),
                model=item.get('device_model', ''),
                _ipaddr=get_ip(ip) if ip else None,
                hardware_version=item.get('hardware_ver'),
                firmware_version=item.get('software_ver'),
                internet_status=item.get('inet_status'),
                group_status=item.get('group_status'),
                signal_2g=self._to_int(signal.get('band2_4')),
                signal_5g=self._to_int(signal.get('band5')),
                rx_rate_2g=self._to_int(rx.get('band2_4')),
                rx_rate_5g=self._to_int(rx.get('band5')),
                tx_rate_2g=self._to_int(tx.get('band2_4')),
                tx_rate_5g=self._to_int(tx.get('band5')),
                # A master reports an empty 'previous'; only slaves have a parent.
                _parent_macaddr=get_mac(parent) if parent else None,
                wired_ports=self._to_int(item.get('port_count')),
            ))

        return nodes

    @staticmethod
    def _to_int(value) -> int | None:
        """The firmware mixes ints and numeric strings across these fields."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _fetch_devices(self) -> list:
        return self.request('admin/device?form=device_list', dumps({"operation": "read"})).get(
            'device_list', [])

    def get_status(self) -> Status:
        data = self.request('admin/network?form=wan_ipv4', dumps({'operation': 'read'}))

        status = Status()
        wan_info = get_value(data, ['wan', 'ip_info']) or get_value(data, ['wan', 'mobile_cpe']) or {}
        element = wan_info.get('mac')
        status._wan_macaddr = get_mac(element) if element else None
        status._lan_macaddr = get_mac(get_value(data, ['lan', 'ip_info', 'mac']))
        element = wan_info.get('ip')
        status._wan_ipv4_addr = get_ip(element) if element else None
        element = get_value(data, ['lan', 'ip_info', 'ip'])
        status._lan_ipv4_addr = get_ip(element) if element else None
        element = wan_info.get('gateway')
        status._wan_ipv4_gateway = get_ip(element) if element else None
        status.conn_type = get_value(data, ['wan', 'dial_type'])

        data = self.request('admin/network?form=performance', dumps({"operation": "read"}))
        status.mem_usage = data.get('mem_usage')
        status.cpu_usage = data.get('cpu_usage')

        data = self.request('admin/wireless?form=wlan', dumps({'operation': 'read'}))
        states = self._wifi_states(data)
        status.wifi_2g_enable = states.get(Connection.HOST_2G)
        status.guest_2g_enable = states.get(Connection.GUEST_2G)
        status.wifi_5g_enable = states.get(Connection.HOST_5G)
        status.guest_5g_enable = states.get(Connection.GUEST_5G)
        status.wifi_6g_enable = states.get(Connection.HOST_6G)
        status.guest_6g_enable = states.get(Connection.GUEST_6G)

        devices = []
        data = self.request('admin/client?form=client_list', dumps(
            {"operation": "read", "params": {"device_mac": "default"}})).get('client_list', [])

        for item in data:
            if not item.get('online'):
                continue
            conn = self._map_wire_type(item)
            if conn == Connection.WIRED:
                status.wired_total += 1
            elif conn.is_host_wifi():
                status.wifi_clients_total += 1
            elif conn.is_guest_wifi():
                status.guest_clients_total += 1
            elif conn.is_iot():
                if status.iot_clients_total is None:
                    status.iot_clients_total = 0
                status.iot_clients_total += 1

            device = Device(conn,
                            get_mac(item.get('mac', '00:00:00:00:00:00')),
                            get_ip(item.get('ip', '0.0.0.0')),
                            self._decode_name(item['name']))
            device.down_speed = item.get('down_speed')
            device.up_speed = item.get('up_speed')
            devices.append(device)

        status.clients_total = (status.wired_total + status.wifi_clients_total + status.guest_clients_total
                                + (0 if status.iot_clients_total is None else status.iot_clients_total))
        status.devices = devices

        return status

    def get_ipv4_status(self) -> IPv4Status:
        ipv4_status = IPv4Status()
        data = self.request('admin/network?form=wan_ipv4', dumps({'operation': 'read'}))
        wan_info = get_value(data, ['wan', 'ip_info']) or get_value(data, ['wan', 'mobile_cpe']) or {}
        element = wan_info.get('mac')
        ipv4_status._wan_macaddr = get_mac(element if element else '00:00:00:00:00:00')
        element = wan_info.get('ip')
        ipv4_status._wan_ipv4_ipaddr = get_ip(element) if element else None
        element = wan_info.get('gateway')
        ipv4_status._wan_ipv4_gateway = get_ip(element) if element else None
        element = get_value(data, ['wan', 'dial_type'])
        ipv4_status._wan_ipv4_conntype = element if element else ''
        element = wan_info.get('mask')
        ipv4_status._wan_ipv4_netmask = get_ip(element) if element else None
        element = wan_info.get('dns1')
        ipv4_status._wan_ipv4_pridns = get_ip(element if element else '0.0.0.0')
        element = wan_info.get('dns2')
        ipv4_status._wan_ipv4_snddns = get_ip(element if element else '0.0.0.0')
        element = get_value(data, ['lan', 'ip_info', 'mac'])
        ipv4_status._lan_macaddr = get_mac(element if element else '00:00:00:00:00:00')
        element = get_value(data, ['lan', 'ip_info', 'ip'])
        ipv4_status._lan_ipv4_ipaddr = get_ip(element if element else '0.0.0.0')
        ipv4_status.lan_ipv4_dhcp_enable = False
        element = get_value(data, ['lan', 'ip_info', 'mask'])
        ipv4_status._lan_ipv4_netmask = get_ip(element if element else '0.0.0.0')

        return ipv4_status

    def get_lte_status(self) -> LTEStatus:
        data = self.request('admin/network?form=internet', dumps({"operation": "read"}))
        status = LTEStatus()
        cpe = data.get('mobile_cpe', {})

        status.enable = 1 if cpe.get('dial_status') == 'connected' else 0
        status.connect_status = 1 if cpe.get('dial_status') == 'connected' else 0

        network_type_map = {
            'lte': 3,
            'lte_plus': 7,
            '5g_nr': 8,
            '5g_nsa': 8,
            '5g_sa': 8,
            'wcdma': 2,
            'gsm': 1,
        }
        status.network_type = network_type_map.get(cpe.get('network_type', ''), 0)

        sim_status_map = {
            'ready': 3,
            'locked': 4,
            'absent': 1,
            'error': 2,
        }
        status.sim_status = sim_status_map.get(cpe.get('sim_status', ''), 0)

        status.total_statistics = cpe.get('data_usage')
        status.cur_rx_speed = cpe.get('downlink_rate')
        status.cur_tx_speed = cpe.get('uplink_rate')

        sig = cpe.get('signal_strength')
        status.sig_level = round(sig / 25) if sig is not None else None

        status.rsrp = cpe.get('rsrp')
        status.rsrq = cpe.get('rsrq')

        snr = cpe.get('snr')
        status.snr = round(snr * 10) if snr is not None else None

        profile = cpe.get('profile_name')
        if profile:
            status.isp_name = self._decode_name(profile)

        return status

    def authorize(self) -> None:
        try:
            self._retry_request(self._authorize_fresh)
        except Timeout as err:
            # A hung login POST while keys/auth still answer is a known Deco
            # firmware stall; retries will not un-stick it — reboot the main node.
            raise ClientException(
                'TplinkRouter - {} - authorize timed out after retries. '
                'If the Deco web UI still works, reboot the main node '
                '(power-cycle or Tether "Restart network").'
                .format(self.__class__.__name__)
            ) from err

    def _authorize_fresh(self) -> None:
        """Clear session/RSA material so each attempt starts a clean handshake."""
        self._reset_session()
        super().authorize()

    def _reset_session(self) -> None:
        self._logged = False
        self._stok = ''
        self._sysauth = ''
        self._pwdNN = ''
        self._seq = ''

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        return self._retry_request(self._request_with_reauth, path, data, ignore_response, ignore_errors)

    def _request_with_reauth(self, path: str, data: str, ignore_response: bool = False,
                             ignore_errors: bool = False) -> dict | None:
        try:
            return super().request(path, data, ignore_response, ignore_errors)
        except ClientError:
            # Deco allows only one admin session; another login (app/UI/script)
            # evicts ours and subsequent calls fail quickly with ClientError.
            self.authorize()
            return super().request(path, data, ignore_response, ignore_errors)

    def _retry_request(self, callback: Callable, *args):
        retries = 0
        while True:
            try:
                return callback(*args)
            except Timeout as err:
                if retries >= self._RETRY_MAX:
                    raise err
                retries += 1
                # Back off so a wedged login endpoint is not hammered immediately.
                sleep(min(2 ** retries, 8))

    def _map_wire_type(self, data: dict) -> Connection:
        if data.get('wire_type') == 'wired':
            return Connection.WIRED
        mapping = {'band2_4': {'main': Connection.HOST_2G, 'guest': Connection.GUEST_2G, 'iot': Connection.IOT_2G},
                   'band5': {'main': Connection.HOST_5G, 'guest': Connection.GUEST_5G, 'iot': Connection.IOT_5G},
                   'band6': {'main': Connection.HOST_6G, 'guest': Connection.GUEST_6G, 'iot': Connection.IOT_6G}
                   }
        result = get_value(mapping, [data.get('connection_type'), data.get('interface')])

        return result if result else Connection.UNKNOWN

    @staticmethod
    def _get_login_data(crypted_pwd: str) -> str:
        data = {
            "params": {"password": crypted_pwd},
            "operation": "login",
        }

        return dumps(data)

    def _is_valid_response(self, data: dict) -> bool:
        return 'error_code' in data and data['error_code'] == 0

    def _decode_name(self, data: str) -> str:
        try:
            return b64decode(data).decode()
        except Exception:
            return data
