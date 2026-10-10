from unittest import TestCase, main
from unittest.mock import Mock, patch
from urllib.parse import parse_qs
from requests.exceptions import ConnectionError, Timeout

from tplinkrouterc6u import TplinkRE813XERouter, Connection, Firmware, Status, IPv4Status, WifiStatus
from tplinkrouterc6u.common.exception import ClientException, ClientError


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

    def test_supports_false_for_short_password(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'short')
        self.assertFalse(client.supports())

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

    def test_authorize_requires_web_encrypted_password(self) -> None:
        client = TplinkRE813XERouter('http://192.168.0.1', 'short')
        with self.assertRaises(ClientException) as ctx:
            client.authorize()
        self.assertIn('web encrypted password', str(ctx.exception))

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
                self.assertIsNone(failed.cpu_usage)
                self.assertIsNone(failed.mem_usage)
                self.assertEqual(failed.wifi_clients_total, 2)
                self.assertEqual(recovered.cpu_usage, 0)
                self.assertEqual(recovered.mem_usage, 0.54)
                self.assertEqual(performance.call_count, 3)

    def test_performance_recovers_after_empty_or_malformed_response(self) -> None:
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
        for _ in range(2):
            status = client.get_status()
            self.assertIsNone(status.cpu_usage)
            self.assertIsNone(status.mem_usage)
            self.assertEqual(status.wifi_clients_total, 0)
        self.assertEqual(performance.call_count, 2)

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
        self.assertEqual(params['txpower'], ['high'])

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

    def test_re700x_alias(self) -> None:
        from tplinkrouterc6u import TplinkRe700XRouter
        self.assertIs(TplinkRe700XRouter, TplinkRE813XERouter)

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

    def test_provider_registers_before_c5400x(self) -> None:
        from tplinkrouterc6u import TplinkRouterProvider, TplinkC5400XRouter
        clients = list(TplinkRouterProvider.get_clients().keys())
        self.assertLess(
            clients.index(TplinkRE813XERouter.__name__),
            clients.index(TplinkC5400XRouter.__name__),
        )


if __name__ == '__main__':
    main()
