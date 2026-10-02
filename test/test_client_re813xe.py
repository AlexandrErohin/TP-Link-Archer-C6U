from unittest import TestCase, main
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

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
        self.assertFalse(client._perf_status)
        self.assertIn('admin/status?form=perf', calls)

    def test_get_ipv4_status(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            self.assertEqual(path, 'admin/network?form=lan_ipv4')
            return {
                'lan_macaddr': '11-22-33-44-55-66',
                'lan_ip': '192.168.0.2',
                'lan_netmask': '255.255.255.0',
            }

        client.request = request  # type: ignore[method-assign]
        ipv4 = client.get_ipv4_status()
        self.assertIsInstance(ipv4, IPv4Status)
        self.assertEqual(ipv4.lan_macaddr, '11-22-33-44-55-66')
        self.assertEqual(ipv4.lan_ipv4_ipaddr, '192.168.0.2')
        self.assertEqual(ipv4.lan_ipv4_netmask, '255.255.255.0')

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
        for wifi in (Connection.GUEST_2G, Connection.IOT_5G, Connection.HOST_MLO_2G):
            with self.subTest(wifi=wifi):
                with self.assertRaises(ValueError):
                    client.set_wifi(wifi, True)

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
