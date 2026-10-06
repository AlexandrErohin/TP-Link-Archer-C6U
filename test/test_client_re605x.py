from unittest import TestCase, main
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from requests import Timeout

from tplinkrouterc6u import TplinkRE605XRouter, TplinkRE813XERouter, TplinkRouterProvider, Connection
from tplinkrouterc6u.common.exception import ClientException, ClientError


class TestTplinkRE605XRouter(TestCase):
    def test_public_identification_and_provider_order(self):
        with patch('tplinkrouterc6u.client.re605x.post') as post:
            post.return_value.json.return_value = {'success': True, 'data': {'model': 'RE605X'}}
            client = TplinkRouterProvider.get_client('http://192.0.2.1', 'test-local-password')
            self.assertIsInstance(client, TplinkRE605XRouter)
            self.assertFalse(client._logged)
            self.assertEqual(post.call_args.kwargs['data'], 'operation=read')
            self.assertNotIn('password', post.call_args.kwargs['data'])
            for data in ({'success': False}, {'success': True, 'data': {'model': 'Archer AX73'}}, None):
                post.return_value.json.return_value = data
                self.assertFalse(client.supports())
            post.side_effect = Timeout()
            self.assertFalse(client.supports())

    def test_plaintext_login_encrypts_and_restores_password(self):
        key = RSA.generate(1024)
        password = 'test-local-password'
        client = TplinkRE605XRouter('http://192.0.2.1', password, timeout=7, verify_ssl=False)
        with patch('tplinkrouterc6u.client.re605x.post') as probe, \
                patch('tplinkrouterc6u.client.re813xe.post') as login:
            probe.return_value.json.return_value = {'success': True, 'data': {
                'password': [format(key.n, 'x'), format(key.e, 'x')]}}
            login.return_value.json.return_value = {'success': True, 'data': {'stok': 'test-token'}}
            login.return_value.headers = {'set-cookie': 'sysauth=test-cookie; Path=/'}
            client.authorize()
            encrypted = parse_qs(login.call_args.kwargs['data'])['password'][0]
            self.assertEqual(PKCS1_v1_5.new(key).decrypt(bytes.fromhex(encrypted), None), password.encode())
            self.assertEqual(probe.call_args.kwargs['timeout'], 7)
            self.assertFalse(probe.call_args.kwargs['verify'])
            self.assertTrue(client._logged)
            self.assertEqual(client.password, password)
            with patch.object(client, 'request') as request:
                client.logout()
                request.assert_called_once_with('admin/system?form=logout', 'operation=write', ignore_response=True)
            self.assertFalse(client._logged)

    def test_web_encrypted_password_and_safe_login_failure(self):
        password = 'a' * 256
        logger = Mock()
        client = TplinkRE605XRouter('http://192.0.2.1', password, logger=logger)
        with patch('tplinkrouterc6u.client.re605x.post') as probe, \
                patch('tplinkrouterc6u.client.re813xe.post') as login:
            login.return_value.json.return_value = {'data': {'stok': 'test-token'}}
            login.return_value.headers = {'set-cookie': 'sysauth=test-cookie; Path=/'}
            client.authorize()
            probe.assert_not_called()
            self.assertEqual(parse_qs(login.call_args.kwargs['data'])['password'], [password])
            login.return_value.json.side_effect = ValueError('private-session-data')
            with self.assertRaises(ClientException) as ctx:
                client.authorize()
            self.assertNotIn('private-session-data', str(ctx.exception))
            logger.debug.assert_not_called()
            self.assertEqual(client.password, password)
            self.assertIs(client._logger, logger)
            self.assertFalse(client._logged)
            self.assertEqual(client._stok, '')
            self.assertEqual(client._sysauth, '')

    def test_bad_key_restores_local_password(self):
        client = TplinkRE605XRouter('http://192.0.2.1', 'test-local-password')
        with patch('tplinkrouterc6u.client.re605x.post') as post:
            post.return_value.json.return_value = {'data': {'password': ['invalid', '010001']}}
            with self.assertRaises(ClientException):
                client.authorize()
        self.assertEqual(client.password, 'test-local-password')

    def test_phy_fields_and_missing_values(self):
        for rx, tx in ((0, 72), (None, None)):
            device = TplinkRE605XRouter._device_from_item(Connection.HOST_2G, {
                'mac': '02-00-00-00-00-01', 'ip': '192.0.2.10', 'name': 'client-1',
                'rxrate': rx, 'txrate': tx})
            self.assertEqual(device.rx_rate, rx)
            self.assertEqual(device.tx_rate, tx)
            self.assertIsNone(device.down_speed)
            self.assertIsNone(device.up_speed)
            self.assertEqual(device.ap_name, 'RE605X')

    def test_status_repeater_fixtures_and_disconnect(self):
        client = TplinkRE605XRouter('http://192.0.2.1', 'test-local-password')
        replies = {
            'admin/status?form=ap_status': {
                'wireless_2g_enable': 'on', 'wireless_5g_enable': 'on', 'wirelessCount': 1,
                'wirelessGrid': [{'mac': '02-00-00-00-00-01', 'ip': '192.0.2.10', 'name': 'client-1',
                                  'type': '2.4GHz', 'rxrate': 54, 'txrate': 72}]},
            'admin/network?form=lan_ipv4': {'lan_ip': '192.0.2.1', 'lan_macaddr': '02-00-00-00-00-02'},
            'admin/status?form=status_device': {'wired_ip': '192.0.2.1'},
            'admin/status?form=perf': {'cpu_usage': 0.05, 'mem_usage': 0.3},
            'admin/status?form=rootAP': {
                'ap_rssi_24g': -70, 'ap_rssi_5g': -71, '2grxrate': 0, '2gtxrate': 72,
                '5grxrate': 648, '5gtxrate': 576, 'ap_channel_24g': 11, 'ap_channel_5g': 36},
            'admin/status?form=repeater': {
                'repeater_conn_24g': 'connected', 'repeater_conn_5g': 'connected', 'internet_status': 'connected'},
            'admin/high_speed?form=settings': {'connect_status': 'dual', 'enable': False},
            'admin/easy_mesh?form=mesh_info': {'mesh_enable': True},
        }

        def request(path, *args):
            if path not in replies:
                raise ClientError('no such callback')
            return replies[path]

        with patch.object(TplinkRE813XERouter, 'request', side_effect=request) as call:
            status = client.get_status()
            self.assertEqual(status.lan_ipv4_addr, '192.0.2.1')
            self.assertEqual(status.cpu_usage, 0.05)
            self.assertEqual(status.clients_total, 1)
            self.assertEqual(status.devices[0].rx_rate, 54)
            self.assertEqual(client.metrics['backhaul_2g_rx_rate'], 0)
            self.assertEqual(client.metrics['backhaul_5g_rssi'], -71)
            self.assertTrue(client.metrics['mesh_enabled'])
            self.assertIsNone(status.wifi_2g_enable)
            replies['admin/status?form=repeater']['repeater_conn_5g'] = 'disconnected'
            replies['admin/status?form=ap_status']['wirelessGrid'] = []
            replies['admin/status?form=ap_status']['wirelessCount'] = 0
            status = client.get_status()
            self.assertEqual(status.devices, [])
            for field in ('rssi', 'rx_rate', 'tx_rate', 'signal_level'):
                self.assertIsNone(client.metrics[f'backhaul_5g_{field}'])
            paths = [c.args[0] for c in call.call_args_list]
            self.assertEqual(paths.count('admin/status?form=guest'), 1)
            self.assertEqual(paths.count('admin/extend?form=guest_settings'), 1)

    def test_optional_does_not_hide_transient_errors(self):
        client = TplinkRE605XRouter('http://192.0.2.1', 'test-local-password')
        for error in (Timeout('timeout'), ClientError('unauthorized')):
            with patch.object(client, 'request', side_effect=error):
                with self.assertRaises(type(error)):
                    client._request_optional('temporary')
        self.assertNotIn('temporary', client._unsupported)

    def test_writes_rejected_and_logout_allowed(self):
        client = TplinkRE605XRouter('http://192.0.2.1', 'test-local-password')
        with patch.object(TplinkRE813XERouter, 'request') as request:
            with self.assertRaises(ClientException):
                client.reboot()
            for data in ('operation=write', 'operation=read&operation=write', 'operation=delete', ''):
                with self.assertRaises(ClientException):
                    client.request('admin/wireless?form=wireless_2g', data)
            request.assert_not_called()
            client.request('admin/system?form=logout', 'operation=write', ignore_response=True)
            request.assert_called_once()


if __name__ == '__main__':
    main()
