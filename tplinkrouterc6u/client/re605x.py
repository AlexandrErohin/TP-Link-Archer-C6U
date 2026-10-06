from urllib.parse import parse_qs

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from requests import post, RequestException

from tplinkrouterc6u.client.re813xe import TplinkRE813XERouter
from tplinkrouterc6u.common.dataclass import Device, Status
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.common.package_enum import Connection


class TplinkRE605XRouter(TplinkRE813XERouter):
    """Read-only RE605X v2 EU client, tested in wireless repeater mode.

    Accepts a local password or the legacy web-encrypted password. Client
    rx_rate/tx_rate and metrics backhaul rates are PHY rates in Mbit/s,
    not traffic throughput. Wi-Fi writes/reboot have not been validated.
    """

    readonly = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.metrics: dict = {}
        self._unsupported: set[str] = set()

    def supports(self) -> bool:
        # Identify without logging in or submitting credentials to other models.
        try:
            reply = post(
                f'{self.host}/cgi-bin/luci/;stok=/login?form=get_deviceInfo',
                data='operation=read', headers=self._headers_login,
                timeout=self.timeout, verify=self._verify_ssl,
            ).json()
            return bool(reply.get('success') and reply.get('data', {}).get('model', '').upper() == 'RE605X')
        except (RequestException, ValueError, AttributeError):
            return False

    def authorize(self) -> None:
        original, logger = self.password, self._logger
        try:
            if len(original) < 200:
                reply = post(
                    f'{self.host}/cgi-bin/luci/;stok=/login?form=login',
                    data='operation=read', headers=self._headers_login,
                    timeout=self.timeout, verify=self._verify_ssl,
                ).json()
                modulus, exponent = reply['data']['password']
                key = RSA.construct((int(modulus, 16), int(exponent, 16)))
                self.password = PKCS1_v1_5.new(key).encrypt(original.encode('utf-8')).hex()
            # The base exception/log can contain response tokens; suppress it here.
            self._logger = None
            super().authorize()
        except Exception:
            self._logged = False
            self._stok = self._sysauth = ''
            raise ClientException('RE605X authorization failed; check the local password') from None
        finally:
            self.password, self._logger = original, logger

    def request(self, path: str, data: str, ignore_response: bool = False,
                ignore_errors: bool = False) -> dict | list | None:
        operations = parse_qs(data).get('operation', [])
        if operations not in (['read'], ['load']) and not (
                path == 'admin/system?form=logout' and operations == ['write']):
            raise ClientException('RE605X monitoring is read-only')
        return super().request(path, data, ignore_response, ignore_errors)

    def _request_optional(self, path: str, data: str = 'operation=read'):
        if path in self._unsupported:
            return None
        try:
            return self.request(path, data)
        except ClientError as err:
            if 'no such callback' not in str(err):
                raise
            self._unsupported.add(path)
            return None

    @staticmethod
    def _device_from_item(conn: Connection, item: dict) -> Device:
        device = TplinkRE813XERouter._device_from_item(conn, item)
        device.rx_rate, device.tx_rate = device.down_speed, device.up_speed
        device.down_speed = device.up_speed = None
        device.ap_name = 'RE605X'
        return device

    def get_status(self) -> Status:
        status = super().get_status()
        root = self.request('admin/status?form=rootAP', 'operation=read')
        repeater = self.request('admin/status?form=repeater', 'operation=read')
        high = self._request_optional('admin/high_speed?form=settings') or {}
        mesh = self._request_optional('admin/easy_mesh?form=mesh_info') or {}
        metrics = {
            'internet_status': repeater.get('internet_status'),
            'ip_status': repeater.get('ipconn_status'),
            'high_speed_mode': high.get('enable'),
            'backhaul_mode': high.get('connect_status'),
            'mesh_enabled': mesh.get('mesh_enable'),
            'wifi_2g_enabled': status.wifi_2g_enable,
            'wifi_5g_enabled': status.wifi_5g_enable,
        }
        for band, suffix in (('2g', '24g'), ('5g', '5g')):
            connected = repeater.get(f'repeater_conn_{suffix}') == 'connected'
            metrics[f'backhaul_{band}_status'] = repeater.get(f'repeater_conn_{suffix}')
            for field, source in (
                    ('rssi', f'ap_rssi_{suffix}'), ('rx_rate', f'{band}rxrate'),
                    ('tx_rate', f'{band}txrate'), ('signal_level', f'ap_signal_{suffix}')):
                metrics[f'backhaul_{band}_{field}'] = root.get(source) if connected else None
            for field, source in (('channel', 'channel'), ('bssid', 'mac'), ('ssid', 'ssid')):
                metrics[f'backhaul_{band}_{field}'] = root.get(f'ap_{source}_{suffix}')
        self.metrics = metrics
        # Do not advertise Wi-Fi controls whose write format is not validated.
        status.wifi_2g_enable = status.wifi_5g_enable = status.wifi_6g_enable = None
        status.guest_2g_enable = status.guest_5g_enable = status.guest_6g_enable = None
        return status
