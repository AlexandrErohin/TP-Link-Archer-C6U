from unittest import main, TestCase
from unittest.mock import Mock

from requests.cookies import RequestsCookieJar

from tplinkrouterc6u import TPLinkCPE210Client
from tplinkrouterc6u.common.exception import ClientError
from tplinkrouterc6u.common.package_enum import Connection


class TestTPLinkCPE210Client(TestCase):
    def test_authorize_uses_nonce_cookie(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')
        client._session = Mock()
        client._session.cookies = Mock()
        client._session.cookies.clear = Mock()

        jar = RequestsCookieJar()
        jar.set('COOKIE', 'AbCd')

        seed = Mock()
        seed.status_code = 200
        seed.cookies = jar

        login = Mock()
        login.status_code = 200
        login.json.return_value = {"success": True, "status": 0}

        client._session.get.return_value = seed
        client._session.post.return_value = login

        client.authorize()

        call = client._session.post.call_args
        data = call.kwargs['data']
        self.assertEqual(data['nonce'], 'AbCd')
        self.assertTrue(data['encoded'].startswith('admin:'))

    def test_authorize_prefers_http_when_https_provided_and_http_works(self) -> None:
        client = TPLinkCPE210Client(
            "https://192.168.0.25:443",
            "password",
            username="admin",
            timeout=5,
            verify_ssl=False,
        )

        cookiejar = RequestsCookieJar()
        cookiejar.set("COOKIE", "nonce-123")

        seed = Mock()
        seed.status_code = 200
        seed.cookies = cookiejar

        client._session = Mock()
        client._session.get.return_value = seed

        login = Mock()
        login.status_code = 200
        login.json.return_value = {"success": True, "status": 0}
        client._session.post.return_value = login

        client.authorize()

        self.assertTrue(client.host.startswith("http://"))
        post_url = client._session.post.call_args[0][0]
        self.assertTrue(post_url.startswith("http://"))

    def test_supports_success(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')
        client._session = Mock()
        client._session.cookies = Mock()
        client._session.cookies.clear = Mock()

        jar = RequestsCookieJar()
        jar.set('COOKIE', 'nonce')

        seed = Mock()
        seed.status_code = 200
        seed.cookies = jar

        info = Mock()
        info.status_code = 200
        info.json.return_value = {
            'success': True,
            'data': {'ok': True},
        }

        login = Mock()
        login.status_code = 200
        login.json.return_value = {"success": True, "status": 0}

        client._session.get.side_effect = [seed, info]
        client._session.post.return_value = login

        self.assertTrue(client.supports())

    def test_get_data_returns_payload_when_no_data_key(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')
        client._session = Mock()

        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {
            'success': True,
            'version': '1.00',
            'devInfo': 'CPE210',
        }
        client._session.get.return_value = resp

        data = client._get_data('/data/version.json')
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get('devInfo'), 'CPE210')

    def test_get_firmware_maps_from_live_style_payload(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')
        client._session = Mock()

        ver = Mock()
        ver.status_code = 200
        ver.json.return_value = {
            'success': True,
            'version': '1.00',
            'devInfo': 'CPE210',
            'devVer': '2.0',
            'mode': 'accessPoint',
        }

        info = Mock()
        info.status_code = 200
        info.json.return_value = {
            'success': True,
            'data': {
                'deviceName': 'CPE210',
                'hardVersion': 'CPE210 v2.0',
                'firmVersion': '2.2.3 Build 20201110 Rel. 66916 (5553)',
            },
        }

        client._session.get.side_effect = [info, ver]

        fw = client.get_firmware()
        self.assertEqual(fw.firmware_version, '2.2.3 Build 20201110 Rel. 66916 (5553)')
        self.assertEqual(fw.model, 'TP-Link CPE210')
        self.assertEqual(fw.hardware_version, 'CPE210 v2.0')

    def test_reboot_calls_config_reboot_endpoint(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')
        client._session = Mock()

        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {
            'success': True,
            'data': {'wholeTime': 30},
        }
        client._session.get.return_value = resp

        client.reboot()

        call = client._session.get.call_args
        self.assertEqual(call.args[0], 'http://192.168.0.25/data/configReboot.json')
        self.assertIn('_', call.kwargs.get('params', {}))

    def test_set_wifi_rejects_non_host_2g(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')
        with self.assertRaises(ClientError):
            client.set_wifi(Connection.HOST_5G, True)

    def test_set_wifi_posts_wireless_enable_toggle(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')
        client._session = Mock()
        client._logged = True

        get_resp = Mock()
        get_resp.status_code = 200
        get_resp.json.return_value = {
            'success': True,
            'data': {
                'ssid': 'test',
                'wirelessEnable': 1,
            },
        }
        client._session.get.return_value = get_resp

        post_resp = Mock()
        post_resp.status_code = 200
        post_resp.json.return_value = {'success': True, 'data': {}}
        client._session.post.return_value = post_resp

        client.set_wifi(Connection.HOST_2G, False)

        post_call = client._session.post.call_args
        self.assertEqual(post_call.args[0], 'http://192.168.0.25/data/wirelessAp.json')
        self.assertEqual(post_call.kwargs['data']['wirelessEnable'], 0)

    def test_get_status_maps_interface_counters_into_devices(self) -> None:
        client = TPLinkCPE210Client('http://192.168.0.25', 'password', username='admin')

        def fake_get_data(path: str, **params):
            if path == '/data/station.json':
                return [
                    {
                        'mac': 'D8-0D-17-9F-5B-06',
                        'ip': '192.168.0.26',
                        'deviceName': 'CPE210',
                    }
                ]
            if path == '/data/interfaces.json':
                return [
                    {
                        'interface': 'BRIDGE',
                        'ip': '192.168.0.25\n',
                        'mac': '3C-84-6A-B5-74-74',
                        'rxPacket': 10,
                        'txPacket': 20,
                        'rxBytes': '2G',
                        'txBytes': '11M',
                    }
                ]
            raise AssertionError(f'unexpected path: {path}')

        client._get_data = Mock(side_effect=fake_get_data)

        status = client.get_status()
        self.assertEqual(status.clients_total, 1)
        self.assertEqual(status.wifi_clients_total, 1)

        # Expect station device + interface device.
        self.assertEqual(len(status.devices), 2)
        iface = next(d for d in status.devices if d.hostname.startswith('IF:'))
        self.assertFalse(iface.active)
        self.assertEqual(iface.packets_received, 10)
        self.assertEqual(iface.packets_sent, 20)

        # traffic_usage is rxBytes + txBytes in bytes (1024-based units).
        expected = 2 * (1024**3) + 11 * (1024**2)
        self.assertEqual(iface.traffic_usage, expected)


if __name__ == '__main__':
    main()
