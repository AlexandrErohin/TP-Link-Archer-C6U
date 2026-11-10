from copy import deepcopy
from unittest import TestCase, main
from unittest.mock import Mock, patch
from urllib.parse import parse_qs
from requests.exceptions import ConnectionError, Timeout
from macaddress import EUI48

from tplinkrouterc6u import (
    TplinkRE813XERouter, Connection, Firmware, Status, IPv4Status, WifiStatus, RepeaterStatus,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError


# Captured from a live RE700X v1.0 (firmware 1.3.15 Build 20251124) in repeater mode.
# Only SSIDs, MAC addresses and the IP address are anonymised. In this capture both bands share
# one SSID and internet_status == ipconn_status, so tests cannot detect a swap of those pairs.
RE700X_ROOT_AP = {
    'ap_ssid_5g': 'upstream-ssid', 'ap_channel_24g': 0, 'ap_channel_5g': 0, 'ap_signal_5g': '2',
    'ap_mac_5g': 'AA-BB-CC-00-00-02', 'ap_security_24g': '3', 'status': 1, 'show5gFlag': 'true',
    'ap_rssi_24g': -59, '5grxrate': 526, 'ap_enable_24g': 'enable', 'show2gFlag': 'true',
    'ap_signal_24g': '2', '2gtxrate': 144, '2grxrate': 5, 'ap_security_status_5g': '3',
    'ap_enable_5g': 'enable', '5gtxrate': 650, 'ap_mac_24g': 'AA-BB-CC-00-00-00',
    'ap_security_status_24g': '3', 'ap_security_5g': '3', 'ap_ssid_24g': 'upstream-ssid', 'ap_rssi_5g': -63,
}
RE700X_REPEATER = {
    'repeater_conn_5g': 'connected', 'repeater_conn_wired_mesh': 'disconnected', 'wired_dhcp': '0',
    'repeater_mac_24g': '02:00:00:00:00:3C', 'repeater_enable_5g': 'enable', 'wirelink_status_2': 'disconnected',
    'guest_ssid_5g': '', 'wirelink_status_0': 'disconnected', 'show2gFlag': 'true',
    'wirelink_status_1': 'disconnected', 'repeater_security_24g': '2', 'repeater_type': '1',
    'wired_ip': '192.168.0.4', 'guest_enable_24g': 'disable', 'internet_status': 'connected',
    'guest_mac_24g': '', 'guest_mac_5g': '', 'ipconn_status': 'connected', 'wired_type': '0',
    'wirelink_status_3': 'disconnected', 'repeater_security_5g': '2', 'wirelink_status_4': 'disconnected',
    'repeater_channel_5g': 48, 'repeater_conn_24g': 'connected', 'guest_ssid_24g': '',
    'guest_enable_5g': 'disable', 'repeater_ssid_24g': 'upstream-ssid', 'repeater_channel_24g': 1,
    'repeater_enable_24g': 'enable', 'show5gFlag': 'true', 'repeater_ssid_5g': 'upstream-ssid',
    'repeater_mac_5g': '02:00:00:00:00:3B',
}
RE700X_MESH_INFO = {
    'mesh_enable': 'on', 'led_sync_show': False, 'time_sync_enable': 'off', 'time': 30, 'sync_status': '0',
    'status': 0, 'ap_support_mesh': 1, 'time_sync_show': False, 'led_sync_enable': 'off',
}
REPEATER_FORMS: dict = {
    'admin/status?form=rootAP': RE700X_ROOT_AP,
    'admin/status?form=repeater': RE700X_REPEATER,
    'admin/easy_mesh?form=mesh_info': RE700X_MESH_INFO,
}


class TestTplinkRE813XERouter(TestCase):
    def _client(self, password: str = 'x' * 200) -> TplinkRE813XERouter:
        client = TplinkRE813XERouter('http://192.168.0.1', password)
        client._logged = True
        client._stok = 'stok-token'
        client._sysauth = 'sysauth-token'
        return client

    def test_init_auth_state(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        self.assertFalse(client._logged)
        self.assertEqual(client._stok, '')
        self.assertEqual(client._sysauth, '')

    def test_request_requires_authorize(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        with self.assertRaises(ClientException):
            client.request('admin/status?form=ap_status', 'operation=read')

    def test_logout_before_authorize_is_noop(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        client.logout()
        self.assertFalse(client._logged)

    def test_supports_true_when_ap_status_ok_and_form_all_fails(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        client.authorize = Mock()  # type: ignore[method-assign]
        client.logout = Mock()  # type: ignore[method-assign]

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/status?form=ap_status':
                return {'wireless_2g_enable': 'on', 'wirelessGrid': []}
            if path == 'admin/status?form=all':
                raise ClientError('missing Apcfg')
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        self.assertTrue(client.supports())
        client.authorize.assert_called_once()
        client.logout.assert_not_called()

    def test_supports_false_when_form_all_works(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        client.authorize = Mock()  # type: ignore[method-assign]
        client.logout = Mock()  # type: ignore[method-assign]

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/status?form=ap_status':
                return {'wireless_2g_enable': 'on'}
            if path == 'admin/status?form=all':
                return {'wireless_2g_ssid': 'router'}
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        self.assertFalse(client.supports())
        client.logout.assert_called_once()

    def test_supports_false_when_ap_status_lacks_markers(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        client.authorize = Mock()  # type: ignore[method-assign]
        client.logout = Mock()  # type: ignore[method-assign]
        client.request = Mock(return_value={'unrelated': True})  # type: ignore[method-assign]
        self.assertFalse(client.supports())
        client.logout.assert_called_once()

    def test_supports_false_on_authorize_error(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        client.authorize = Mock(side_effect=ClientException('bad login'))  # type: ignore[method-assign]
        client.logout = Mock()  # type: ignore[method-assign]
        self.assertFalse(client.supports())
        client.logout.assert_called_once()

    def test_get_encrypted_password_passthrough_for_long_password(self) -> None:
        password = 'x' * 200
        client = TplinkRE813XERouter('http://192.168.0.1', password)
        self.assertEqual(client._get_encrypted_password(), password)

    @patch('tplinkrouterc6u.client.re813xe.EncryptionWrapper.rsa_encrypt', return_value='enc' * 70)
    @patch('tplinkrouterc6u.client.re813xe.post')
    def test_get_encrypted_password_encrypts_plaintext(self, mock_post, mock_rsa) -> None:
        response = Mock()
        response.json.return_value = {'data': {'password': ['nnhex', '10001']}}
        mock_post.return_value = response

        client = TplinkRE813XERouter('http://192.168.0.1', 'secret')
        self.assertEqual(client._get_encrypted_password(), 'enc' * 70)
        mock_post.assert_called_once()
        self.assertIn('operation=read', mock_post.call_args.args[0])
        mock_rsa.assert_called_once_with('secret', 'nnhex', '10001')

    @patch('tplinkrouterc6u.client.re813xe.post', side_effect=OSError('unreachable'))
    def test_get_encrypted_password_wraps_errors(self, _mock_post) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'secret')
        with self.assertRaises(ClientException) as ctx:
            client._get_encrypted_password()
        self.assertIn('RSA public key', str(ctx.exception))

    def test_str2bool_accepts_numeric_one(self) -> None:
        self.assertTrue(TplinkRE813XERouter._str2bool('1'))
        self.assertTrue(TplinkRE813XERouter._str2bool(1))
        self.assertFalse(TplinkRE813XERouter._str2bool('0'))
        self.assertFalse(TplinkRE813XERouter._str2bool('off'))
        self.assertIsNone(TplinkRE813XERouter._str2bool(None))

    @patch('tplinkrouterc6u.client.re813xe.post')
    def test_authorize_sets_tokens(self, mock_post) -> None:
        response = Mock()
        response.text = '{"success":true}'
        response.json.return_value = {'success': True, 'data': {'stok': 'abc123'}}
        response.headers = {'set-cookie': 'sysauth=cookie-value; Path=/; HttpOnly'}
        mock_post.return_value = response

        client = TplinkRE813XERouter('http://192.168.0.1', 'x' * 200)
        client.authorize()

        self.assertTrue(client._logged)
        self.assertEqual(client._stok, 'abc123')
        self.assertEqual(client._sysauth, 'cookie-value')
        mock_post.assert_called_once()
        self.assertIn('password=' + 'x' * 200, mock_post.call_args.kwargs['data'])

    @patch('tplinkrouterc6u.client.re813xe.post')
    def test_authorize_skips_login_when_already_logged_in(self, mock_post) -> None:
        client = self._client()
        client._get_encrypted_password = Mock(  # type: ignore[method-assign]
            side_effect=AssertionError('must not encrypt when session is active'))
        client.authorize()
        mock_post.assert_not_called()
        self.assertTrue(client._logged)
        self.assertEqual(client._stok, 'stok-token')

    @patch('tplinkrouterc6u.client.re813xe.EncryptionWrapper.rsa_encrypt', return_value='cipherhex')
    @patch('tplinkrouterc6u.client.re813xe.post')
    def test_authorize_encrypts_plaintext_before_login(self, mock_post, mock_rsa) -> None:
        key_response = Mock()
        key_response.json.return_value = {'data': {'password': ['nn', 'ee']}}
        login_response = Mock()
        login_response.text = '{"success":true}'
        login_response.json.return_value = {'success': True, 'data': {'stok': 'tok'}}
        login_response.headers = {'set-cookie': 'sysauth=cookie; Path=/'}
        mock_post.side_effect = [key_response, login_response]

        client = TplinkRE813XERouter('http://192.168.0.1', 'plaintext')
        client.authorize()

        self.assertTrue(client._logged)
        self.assertEqual(client._stok, 'tok')
        mock_rsa.assert_called_once_with('plaintext', 'nn', 'ee')
        self.assertEqual(mock_post.call_count, 2)
        self.assertEqual(mock_post.call_args.kwargs['data'], 'operation=login&password=cipherhex')

    def test_get_firmware(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            self.assertEqual(path, 'admin/firmware?form=upgrade')
            return {
                'hardware_version': '1.6',
                'model': 'RE813XE',
                'firmware_version': '1.0.9 Build 20250801 Rel. 16290',
            }

        client.request = request  # type: ignore[method-assign]
        firmware = client.get_firmware()
        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, '1.6')
        self.assertEqual(firmware.model, 'RE813XE')
        self.assertEqual(firmware.firmware_version, '1.0.9 Build 20250801 Rel. 16290')

    def test_get_status(self) -> None:
        client = self._client()
        calls = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            calls.append(path)
            if path == 'admin/status?form=ap_status':
                return {
                    'wireless_2g_enable': 'on',
                    'wireless_5g_enable': 'off',
                    'wireless_6g_enable': 'on',
                    'wirelessCount': 2,
                    'wirelessGrid': [
                        {'type': '2.4GHz', 'mac': 'AA-BB-CC-DD-EE-01', 'ipaddr': '192.168.0.10', 'name': 'phone'},
                        {'type': '5GHz', 'mac': 'AA-BB-CC-DD-EE-02', 'ip': '192.168.0.11', 'name': 'laptop'},
                    ],
                }
            if path == 'admin/network?form=lan_ipv4':
                return {'lan_macaddr': '11-22-33-44-55-66', 'lan_ip': '192.168.0.2'}
            if path in (
                'admin/status?form=status_device',
                'admin/status?form=guest',
                'admin/extend?form=guest_settings',
            ):
                raise ClientError('optional endpoint missing')
            if path == 'admin/status?form=perf':
                raise ClientError('perf missing')
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.lan_macaddr, '11-22-33-44-55-66')
        self.assertEqual(status.lan_ipv4_addr, '192.168.0.2')
        self.assertTrue(status.wifi_2g_enable)
        self.assertFalse(status.wifi_5g_enable)
        self.assertTrue(status.wifi_6g_enable)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.clients_total, 2)
        self.assertEqual(len(status.devices), 2)
        self.assertEqual(status.devices[0].type, Connection.HOST_2G)
        self.assertEqual(status.devices[1].type, Connection.HOST_5G)
        self.assertIsNone(status.cpu_usage)
        self.assertIsNone(status.mem_usage)
        self.assertIn('admin/status?form=perf', calls)
        self.assertFalse(client._perf_status)
        self.assertFalse(client._perf_ok)

    def test_performance_recovers_after_transient_failure(self) -> None:
        for error in (ConnectionError('connection reset'), Timeout('timeout'), ClientError('temporary error')):
            with self.subTest(error=type(error).__name__):
                client = self._client()
                performance = Mock(side_effect=[
                    {'cpu_usage': 0.04, 'mem_usage': 0.53},
                    error,
                    {'cpu_usage': 0, 'mem_usage': 0.54},
                ])

                def request(path, data):
                    if path == 'admin/status?form=perf':
                        return performance()
                    return {'wirelessCount': 2} if path.endswith('form=ap_status') else {}

                client.request = request
                initial = client.get_status()
                failed = client.get_status()
                recovered = client.get_status()
                self.assertEqual(initial.cpu_usage, 0.04)
                self.assertEqual(initial.mem_usage, 0.53)
                self.assertTrue(client._perf_ok)
                self.assertIsNone(failed.cpu_usage)
                self.assertIsNone(failed.mem_usage)
                self.assertEqual(failed.wifi_clients_total, 2)
                self.assertEqual(recovered.cpu_usage, 0)
                self.assertEqual(recovered.mem_usage, 0.54)
                self.assertEqual(performance.call_count, 3)

    def test_performance_retries_network_errors_before_first_success(self) -> None:
        for error in (ConnectionError('connection reset'), Timeout('timeout')):
            with self.subTest(error=type(error).__name__):
                client = self._client()
                performance = Mock(side_effect=[error, {'cpu_usage': 0.11, 'mem_usage': 0.52}])

                def request(path, data):
                    if path == 'admin/status?form=perf':
                        return performance()
                    return {}

                client.request = request
                failed = client.get_status()
                self.assertIsNone(failed.cpu_usage)
                self.assertIsNone(failed.mem_usage)
                self.assertTrue(client._perf_status)
                self.assertFalse(client._perf_ok)
                recovered = client.get_status()
                self.assertEqual(recovered.cpu_usage, 0.11)
                self.assertEqual(recovered.mem_usage, 0.52)
                self.assertTrue(client._perf_ok)
                self.assertEqual(performance.call_count, 2)

    def test_performance_recovers_after_empty_or_malformed_response(self) -> None:
        # Non-dict payloads are ignored without latching; an empty dict counts
        # as a successful probe (endpoint exists) even when metrics are absent.
        for response in (None, [], {}, 'invalid'):
            with self.subTest(response=response):
                client = self._client()
                performance = Mock(side_effect=[response, {'cpu_usage': 0.09, 'mem_usage': 0.53}])
                client.request = lambda path, data: performance() if path.endswith('form=perf') else {}
                failed = client.get_status()
                recovered = client.get_status()
                self.assertIsNone(failed.cpu_usage)
                self.assertIsNone(failed.mem_usage)
                self.assertEqual(recovered.cpu_usage, 0.09)
                self.assertEqual(recovered.mem_usage, 0.53)
                self.assertEqual(performance.call_count, 2)

    def test_unsupported_performance_does_not_fail_status(self) -> None:
        client = self._client()
        performance = Mock(side_effect=ClientError('unsupported endpoint'))
        client.request = lambda path, data: performance() if path.endswith('form=perf') else {}
        status = client.get_status()
        self.assertIsNone(status.cpu_usage)
        self.assertIsNone(status.mem_usage)
        self.assertEqual(status.wifi_clients_total, 0)
        self.assertFalse(client._perf_status)
        self.assertFalse(client._perf_ok)
        # Second poll must not hit the unsupported endpoint again.
        client.get_status()
        self.assertEqual(performance.call_count, 1)

    def test_get_status_re700x_fixtures(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/status?form=ap_status':
                return {
                    'wireless_2g_enable': 'on',
                    'wireless_5g_enable': 'on',
                    'wirelessCount': 8,
                    'wirelessGrid': [
                        {
                            'mac': '7C-2C-67-D9-E9-14',
                            'type': '2.4GHz',
                            'name': 'esp32c3-D9E914',
                            'rxrate': 108,
                            'txrate': 150,
                            'ipaddr': '192.168.1.52',
                        },
                        {
                            'mac': '26-96-9F-67-1E-C5',
                            'type': '5GHz',
                            'name': 'Mac',
                            'rxrate': 648,
                            'txrate': 960,
                            'ipaddr': '192.168.1.55',
                        },
                    ],
                }
            if path == 'admin/status?form=status_device':
                return {'wired_dhcp': '1', 'wired_ip': '192.168.1.4', 'wired_type': '0'}
            if path == 'admin/network?form=lan_ipv4':
                raise ClientError('no lan_ipv4')
            if path == 'admin/status?form=guest':
                return [
                    {
                        'mac': 'B0-4A-39-98-20-AD',
                        'type': '2.4GHz',
                        'name': 'roborock-vacuum-a51',
                        'rxrate': 150,
                        'txrate': 150,
                        'ipaddr': '192.168.1.51',
                    },
                    {
                        'mac': 'FC-3C-D7-2A-DE-10',
                        'type': '2.4GHz',
                        'name': 'wlan0',
                        'rxrate': 52,
                        'txrate': 65,
                        'ipaddr': '192.168.1.54',
                    },
                ]
            if path == 'admin/extend?form=guest_settings':
                return {
                    'enable_5g': 'off',
                    'enable_2g': 'on',
                    'ssid_2g': 'XYZ',
                    'ssid_5g': 'TP-Link_Guest_5G',
                    'hide_2g': 'off',
                    'hide_5g': 'off',
                    'password': '***',
                    'sec': 'wpa2/wpa3',
                }
            if path == 'admin/status?form=perf':
                raise ClientError('perf missing')
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        status = client.get_status()

        self.assertEqual(status.lan_ipv4_addr, '192.168.1.4')
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertTrue(status.guest_2g_enable)
        self.assertFalse(status.guest_5g_enable)
        self.assertEqual(status.wifi_clients_total, 8)
        self.assertEqual(status.guest_clients_total, 2)
        self.assertEqual(status.clients_total, 10)
        self.assertEqual(len(status.devices), 4)
        guest = [d for d in status.devices if d.type.is_guest_wifi()]
        self.assertEqual(len(guest), 2)
        self.assertEqual(guest[0].type, Connection.GUEST_2G)
        self.assertEqual(guest[0].down_speed, 150)
        # rxrate / txrate are PHY link rates in Mbps: they fill rx_rate / tx_rate, and
        # down_speed / up_speed keep the same values for backward compatibility.
        rates = {d.macaddr: (d.rx_rate, d.tx_rate, d.down_speed, d.up_speed) for d in status.devices}
        self.assertEqual(rates['7C-2C-67-D9-E9-14'], (108, 150, 108, 150))
        self.assertEqual(rates['26-96-9F-67-1E-C5'], (648, 960, 648, 960))
        self.assertEqual(rates['B0-4A-39-98-20-AD'], (150, 150, 150, 150))
        self.assertEqual(rates['FC-3C-D7-2A-DE-10'], (52, 65, 52, 65))

    def test_device_from_item_coerces_string_phy_rates(self) -> None:
        device = TplinkRE813XERouter._device_from_item(
            Connection.HOST_2G,
            {'mac': 'AA-BB-CC-DD-EE-FF', 'ipaddr': '192.168.0.10', 'name': 'phone',
             'rxrate': '108', 'txrate': '150'},
        )
        self.assertEqual((device.rx_rate, device.tx_rate, device.down_speed, device.up_speed),
                         (108, 150, 108, 150))
        self.assertIsInstance(device.rx_rate, int)
        self.assertIsInstance(device.tx_rate, int)

    def test_get_ipv4_status(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/network?form=lan_ipv4':
                return {
                    'lan_macaddr': '11-22-33-44-55-66',
                    'lan_ip': '192.168.0.2',
                    'lan_netmask': '255.255.255.0',
                }
            if path == 'admin/status?form=status_device':
                raise ClientError('unused')
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        ipv4 = client.get_ipv4_status()
        self.assertIsInstance(ipv4, IPv4Status)
        self.assertEqual(ipv4.lan_macaddr, '11-22-33-44-55-66')
        self.assertEqual(ipv4.lan_ipv4_ipaddr, '192.168.0.2')
        self.assertEqual(ipv4.lan_ipv4_netmask, '255.255.255.0')

    def test_get_ipv4_status_falls_back_to_status_device(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/network?form=lan_ipv4':
                raise ClientError('missing')
            if path == 'admin/status?form=status_device':
                return {'wired_ip': '192.168.1.4'}
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        ipv4 = client.get_ipv4_status()
        self.assertEqual(ipv4.lan_ipv4_ipaddr, '192.168.1.4')

    def test_get_ipv4_reservations_empty(self) -> None:
        client = self._client()
        self.assertEqual(client.get_ipv4_reservations(), [])

    def test_get_ipv4_dhcp_leases_skips_non_dict(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            return {'0': {'macaddr': 'AA:BB:CC:DD:EE:FF', 'ipaddr': '192.168.0.20', 'name': 'pc', 'leasetime': '1h'},
                    'meta': 'ignore-me'}

        client.request = request  # type: ignore[method-assign]
        leases = client.get_ipv4_dhcp_leases()
        self.assertEqual(len(leases), 1)
        self.assertEqual(leases[0].ipaddr, '192.168.0.20')
        self.assertEqual(leases[0].hostname, 'pc')

    def test_get_ipv4_dhcp_leases_list_format(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            return [{
                'leasetime': '00:00:38',
                'macaddr': 'a8:46:74:46:14:f8',
                'ipaddr': '192.168.1.59',
                'name': 'bedroom-ble',
            }]

        client.request = request  # type: ignore[method-assign]
        leases = client.get_ipv4_dhcp_leases()
        self.assertEqual(len(leases), 1)
        self.assertEqual(leases[0].hostname, 'bedroom-ble')
        self.assertEqual(leases[0].ipaddr, '192.168.1.59')
        self.assertEqual(leases[0].lease_time, '00:00:38')

    def test_set_wifi_enable_sends_full_payload(self) -> None:
        client = self._client()
        writes = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if data == 'operation=read':
                return {
                    'enable': 'off',
                    'ssid': 'RE813XE',
                    'hidden': 'off',
                    'encryption': 'psk2',
                    'psk_version': 'rsn',
                    'psk_cipher': 'aes',
                    'psk_key': 'secret',
                    'hwmode': '11ax',
                    'htmode': 'HE20',
                    'channel': '6',
                    'txpower': 'high',
                    'twt': 'on',
                    'ofdma': 'on',
                    'mimo': 'on',
                }
            writes.append((path, data))
            return {}

        client.request = request  # type: ignore[method-assign]
        client.set_wifi(Connection.HOST_2G, True)

        self.assertEqual(len(writes), 1)
        path, body = writes[0]
        self.assertEqual(path, 'admin/wireless?form=wireless_2g')
        params = parse_qs(body)
        self.assertEqual(params['operation'], ['write'])
        self.assertEqual(params['enable'], ['on'])
        self.assertEqual(params['disabled_all'], ['off'])
        self.assertEqual(params['ssid'], ['RE813XE'])
        self.assertEqual(params['psk_cipher'], ['aes'])
        self.assertEqual(params['txpower'], ['high'])

    def test_set_wifi_with_psk_cipher(self) -> None:
        client = self._client()
        writes = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if data == 'operation=read':
                return {
                    'enable': 'off',
                    'ssid': 'RE505X',
                    'encryption': 'psk',
                    'psk_version': 'rsn',
                    'psk_cipher': 'aes',
                    'psk_key': 'secret',
                    'hwmode': 'anacax',
                    'htmode': 'auto',
                    'channel': 'auto',
                }
            writes.append((path, data))
            return {}

        client.request = request  # type: ignore[method-assign]
        client.set_wifi(Connection.HOST_5G, True)

        self.assertEqual(len(writes), 1)
        params = parse_qs(writes[0][1])
        self.assertEqual(params['enable'], ['on'])
        self.assertEqual(params['disabled_all'], ['off'])
        self.assertEqual(params['psk_cipher'], ['aes'])

    def test_set_wifi_disable_sends_minimal_payload(self) -> None:
        client = self._client()
        writes = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if data == 'operation=read':
                return {
                    'enable': 'on',
                    'ssid': 'RE813XE-5G',
                    'twt': 'on',
                    'ofdma': 'on',
                    'mimo': 'on',
                    'txpower': 'high',
                }
            writes.append((path, data))
            return {}

        client.request = request  # type: ignore[method-assign]
        client.set_wifi(Connection.HOST_5G, False)

        params = parse_qs(writes[0][1])
        self.assertEqual(params['enable'], ['off'])
        self.assertEqual(params['disabled_all'], ['on'])
        self.assertNotIn('ssid', params)
        self.assertNotIn('txpower', params)

    def test_set_wifi_6g_uses_psc_enable(self) -> None:
        client = self._client()
        writes = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if data == 'operation=read':
                return {
                    'enable': 'off',
                    'ssid': 'RE813XE-6G',
                    'hidden': 'off',
                    'encryption': 'psk2',
                    'psk_version': 'rsn',
                    'psk_key': 'secret',
                    'hwmode': '11ax',
                    'htmode': 'HE80',
                    'channel': '37',
                    'pscEnable': 'on',
                    'twt': 'on',
                    'ofdma': 'on',
                    'mimo': 'on',
                }
            writes.append(data)
            return {}

        client.request = request  # type: ignore[method-assign]
        client.set_wifi(Connection.HOST_6G, True)
        params = parse_qs(writes[0])
        self.assertEqual(params['pscEnable'], ['on'])
        self.assertNotIn('txpower', params)

    def test_set_wifi_unsupported_raises(self) -> None:
        client = self._client()
        for wifi in (Connection.IOT_5G, Connection.HOST_MLO_2G, Connection.WIRED):
            with self.subTest(wifi=wifi):
                with self.assertRaises(ValueError):
                    client.set_wifi(wifi, True)

    def test_set_guest_wifi(self) -> None:
        client = self._client()
        writes = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            self.assertEqual(path, 'admin/extend?form=guest_settings')
            if data == 'operation=read':
                return {
                    'enable_2g': 'off',
                    'enable_5g': 'off',
                    'ssid_2g': 'Guest',
                    'ssid_5g': 'Guest5',
                    'hide_2g': 'off',
                    'password': 'old',
                    'sec': 'wpa2/wpa3',
                }
            writes.append(data)
            return {}

        client.request = request  # type: ignore[method-assign]
        client.set_wifi(Connection.GUEST_2G, True, ssid='NewGuest')
        params = parse_qs(writes[0])
        self.assertEqual(params['operation'], ['write'])
        self.assertEqual(params['enable_2g'], ['on'])
        self.assertEqual(params['ssid_2g'], ['NewGuest'])
        self.assertEqual(params['enable_5g'], ['off'])

    def test_get_guest_wifi(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            self.assertEqual(path, 'admin/extend?form=guest_settings')
            return {
                'enable_2g': 'on',
                'ssid_2g': 'XYZ',
                'hide_2g': 'off',
                'password': 'secret',
                'sec': 'wpa2/wpa3',
            }

        client.request = request  # type: ignore[method-assign]
        wifi = client.get_wifi(Connection.GUEST_2G)
        self.assertTrue(wifi.enable)
        self.assertEqual(wifi.ssid, 'XYZ')
        self.assertFalse(wifi.hidden)
        self.assertEqual(wifi.psk_key, 'secret')
        self.assertEqual(wifi.encryption, 'wpa2/wpa3')

    def test_get_wifi(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            self.assertEqual(path, 'admin/wireless?form=wireless_2g')
            return {
                'enable': 'on',
                'ssid': 'RE813XE',
                'hidden': 'off',
                'encryption': 'psk2',
                'psk_key': 'secret',
                'channel': '11',
            }

        client.request = request  # type: ignore[method-assign]
        wifi = client.get_wifi(Connection.HOST_2G)
        self.assertIsInstance(wifi, WifiStatus)
        self.assertTrue(wifi.enable)
        self.assertEqual(wifi.ssid, 'RE813XE')
        self.assertFalse(wifi.hidden)
        self.assertEqual(wifi.channel, 11)

    def test_reboot(self) -> None:
        client = self._client()
        calls = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            calls.append((path, data, ignore_response))
            return None

        client.request = request  # type: ignore[method-assign]
        client.reboot()
        self.assertEqual(calls, [('admin/system?form=reboot', 'operation=write', True)])

    def _repeater_client(self, forms: dict) -> tuple[TplinkRE813XERouter, list]:
        client = self._client()
        calls = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            calls.append((path, data))
            reply = forms[path]
            if isinstance(reply, Exception):
                raise reply
            return reply

        client.request = request  # type: ignore[method-assign]
        return client, calls

    def test_get_repeater_status_re700x_fixtures(self) -> None:
        client, calls = self._repeater_client(deepcopy(REPEATER_FORMS))

        repeater = client.get_repeater_status()

        self.assertIsInstance(repeater, RepeaterStatus)
        self.assertEqual(sorted(calls), sorted((path, 'operation=read') for path in REPEATER_FORMS))
        self.assertEqual(repeater.connection_2g, 'connected')
        self.assertEqual(repeater.connection_5g, 'connected')
        self.assertTrue(repeater.connected_2g)
        self.assertTrue(repeater.connected_5g)
        self.assertEqual(repeater.internet_status, 'connected')
        self.assertEqual(repeater.ipconn_status, 'connected')
        self.assertEqual(repeater.ssid_2g, 'upstream-ssid')
        self.assertEqual(repeater.ssid_5g, 'upstream-ssid')
        self.assertEqual(repeater.bssid_2g, 'AA-BB-CC-00-00-00')
        self.assertEqual(repeater.bssid_5g, 'AA-BB-CC-00-00-02')
        self.assertIsInstance(repeater.bssid_5g_macaddress, EUI48)
        self.assertEqual(repeater.rssi_2g, -59)
        self.assertEqual(repeater.rssi_5g, -63)
        self.assertEqual(repeater.rx_rate_2g, 5)
        self.assertEqual(repeater.tx_rate_2g, 144)
        self.assertEqual(repeater.rx_rate_5g, 526)
        self.assertEqual(repeater.tx_rate_5g, 650)
        # Mesh enabled but not synced must stay two separate values.
        self.assertTrue(repeater.mesh_enable)
        self.assertEqual(repeater.mesh_sync_status, '0')

    def test_get_repeater_status_disconnected_band_reports_no_readings(self) -> None:
        # A band that is not connected must not report RSSI or PHY rates for that band.
        # Derived state: one field of the real capture changed. 'disconnected' is the
        # firmware's own word (repeater_conn_wired_mesh in the same capture).
        bands = {
            '2g': ('repeater_conn_24g', 'AA-BB-CC-00-00-00', '5g', (-63, 526, 650)),
            '5g': ('repeater_conn_5g', 'AA-BB-CC-00-00-02', '2g', (-59, 5, 144)),
        }
        for band, (conn_key, bssid, other, other_readings) in bands.items():
            with self.subTest(band=band):
                forms = deepcopy(REPEATER_FORMS)
                forms['admin/status?form=repeater'][conn_key] = 'disconnected'
                client, _ = self._repeater_client(forms)

                repeater = client.get_repeater_status()

                self.assertEqual(getattr(repeater, f'connection_{band}'), 'disconnected')
                self.assertFalse(getattr(repeater, f'connected_{band}'))
                for field in ('rssi', 'rx_rate', 'tx_rate'):
                    self.assertIsNone(getattr(repeater, f'{field}_{band}'))
                # The upstream access point identity is configuration, not a reading: keep it.
                self.assertEqual(getattr(repeater, f'ssid_{band}'), 'upstream-ssid')
                self.assertEqual(getattr(repeater, f'bssid_{band}'), bssid)
                # The connected band is unaffected.
                self.assertEqual(
                    tuple(getattr(repeater, f'{field}_{other}') for field in ('rssi', 'rx_rate', 'tx_rate')),
                    other_readings)

    def test_get_repeater_status_unknown_connection_reports_no_readings(self) -> None:
        # With the repeater form unsupported the connection state is unknown (None, not
        # 'disconnected'). RSSI and PHY rates are then not reported; SSID and BSSID are kept.
        forms = deepcopy(REPEATER_FORMS)
        forms['admin/status?form=repeater'] = ClientError(
            'Response with error; Request admin/status?form=repeater'
            ' - Response {"errorcode": "no such callback", "success": false}')
        client, _ = self._repeater_client(forms)

        repeater = client.get_repeater_status()

        for band in ('2g', '5g'):
            self.assertIsNone(getattr(repeater, f'connection_{band}'))
            self.assertFalse(getattr(repeater, f'connected_{band}'))
            for field in ('rssi', 'rx_rate', 'tx_rate'):
                self.assertIsNone(getattr(repeater, f'{field}_{band}'))
            self.assertEqual(getattr(repeater, f'ssid_{band}'), 'upstream-ssid')
        self.assertEqual(repeater.bssid_2g, 'AA-BB-CC-00-00-00')
        self.assertEqual(repeater.bssid_5g, 'AA-BB-CC-00-00-02')
        self.assertIsNone(repeater.internet_status)

    def test_get_repeater_status_unsupported_form_is_skipped_after_first_reply(self) -> None:
        # The firmware answers a missing form with {"errorcode": "no such callback", "success": false}
        # (seen on RE605X for admin/extend?form=guest_settings). Only that reply marks a form
        # unsupported; the other forms are still read on every call.
        forms = deepcopy(REPEATER_FORMS)
        forms['admin/easy_mesh?form=mesh_info'] = ClientError(
            'TplinkRouter - TplinkRE813XERouter - Response with error; Request admin/easy_mesh?form=mesh_info'
            ' - Response {"errorcode": "no such callback", "success": false}')
        client, calls = self._repeater_client(forms)

        first = client.get_repeater_status()
        second = client.get_repeater_status()

        for repeater in (first, second):
            self.assertIsNone(repeater.mesh_enable)
            self.assertIsNone(repeater.mesh_sync_status)
            self.assertEqual(repeater.rssi_5g, -63)
            self.assertEqual(repeater.internet_status, 'connected')
        paths = [path for path, _ in calls]
        self.assertEqual(paths.count('admin/easy_mesh?form=mesh_info'), 1)
        self.assertEqual(paths.count('admin/status?form=rootAP'), 2)
        self.assertEqual(paths.count('admin/status?form=repeater'), 2)

    def test_get_repeater_status_other_errors_raise_and_are_not_latched(self) -> None:
        # Transient failures (#244 contract): this call fails, the next call reads the form again.
        for error in (ClientError('Response with error; Request admin/status?form=rootAP - Response 500'),
                      Timeout('timeout'), ConnectionError('connection reset')):
            forms = deepcopy(REPEATER_FORMS)
            forms['admin/status?form=rootAP'] = error
            client, calls = self._repeater_client(forms)

            with self.assertRaises(type(error)):
                client.get_repeater_status()

            forms['admin/status?form=rootAP'] = deepcopy(RE700X_ROOT_AP)
            repeater = client.get_repeater_status()
            self.assertEqual(repeater.rssi_5g, -63)
            self.assertEqual([path for path, _ in calls].count('admin/status?form=rootAP'), 2)
            self.assertEqual(client._unsupported_forms, set())

    def test_get_repeater_status_zero_rate_is_kept(self) -> None:
        # A connected band can report a PHY rate of 0 (RE605X fixture in #241); 0 is a value, not None.
        # Derived state: one field of the real capture changed per case.
        for key, field in (('2grxrate', 'rx_rate_2g'), ('2gtxrate', 'tx_rate_2g'),
                           ('5grxrate', 'rx_rate_5g'), ('5gtxrate', 'tx_rate_5g')):
            with self.subTest(key=key):
                forms = deepcopy(REPEATER_FORMS)
                forms['admin/status?form=rootAP'][key] = 0
                client, _ = self._repeater_client(forms)

                self.assertEqual(getattr(client.get_repeater_status(), field), 0)

    def test_get_repeater_status_mesh_off(self) -> None:
        # Derived state: mesh_enable 'off'. 'off' is the firmware's own value for the
        # time_sync_enable / led_sync_enable switches in the same capture.
        forms = deepcopy(REPEATER_FORMS)
        forms['admin/easy_mesh?form=mesh_info']['mesh_enable'] = 'off'
        client, _ = self._repeater_client(forms)

        repeater = client.get_repeater_status()

        self.assertIs(repeater.mesh_enable, False)
        self.assertEqual(repeater.mesh_sync_status, '0')

    def test_get_repeater_status_ignores_non_dict_reply(self) -> None:
        # request() can return a list; a form that does not answer with an object is ignored.
        forms = deepcopy(REPEATER_FORMS)
        forms['admin/status?form=rootAP'] = [RE700X_ROOT_AP]
        client, _ = self._repeater_client(forms)

        repeater = client.get_repeater_status()

        self.assertIsNone(repeater.rssi_5g)
        self.assertIsNone(repeater.bssid_2g)
        self.assertIsNone(repeater.bssid_5g)
        self.assertEqual(repeater.internet_status, 'connected')
        self.assertTrue(repeater.mesh_enable)

    def test_get_repeater_status_coerces_string_numbers_and_sync_status(self) -> None:
        # Some firmwares may JSON-encode rates/RSSI as strings and sync_status as an int.
        forms = deepcopy(REPEATER_FORMS)
        forms['admin/status?form=rootAP'].update({
            'ap_rssi_24g': '-59', 'ap_rssi_5g': '-63',
            '2grxrate': '5', '2gtxrate': '144', '5grxrate': '526', '5gtxrate': '650',
        })
        forms['admin/easy_mesh?form=mesh_info']['sync_status'] = 0
        client, _ = self._repeater_client(forms)

        repeater = client.get_repeater_status()

        self.assertEqual(repeater.rssi_2g, -59)
        self.assertEqual(repeater.rssi_5g, -63)
        self.assertEqual(repeater.rx_rate_2g, 5)
        self.assertEqual(repeater.tx_rate_2g, 144)
        self.assertEqual(repeater.rx_rate_5g, 526)
        self.assertEqual(repeater.tx_rate_5g, 650)
        self.assertEqual(repeater.mesh_sync_status, '0')
        self.assertIsInstance(repeater.mesh_sync_status, str)

    def test_provider_registers_before_c5400x(self) -> None:
        from tplinkrouterc6u import TplinkRouterProvider, TplinkC5400XRouter
        clients = list(TplinkRouterProvider.get_clients().keys())
        self.assertLess(
            clients.index(TplinkRE813XERouter.__name__),
            clients.index(TplinkC5400XRouter.__name__),
        )


if __name__ == '__main__':
    main()
