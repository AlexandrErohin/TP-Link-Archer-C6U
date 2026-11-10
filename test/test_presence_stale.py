import unittest
from tplinkrouterc6u import TplinkRouterSG, ClientException


class PresenceTest(unittest.TestCase):
    def status(self, uptime, primary=False):
        primary_host = {'macaddr': '02:00:00:00:00:02', 'ipaddr': '192.0.2.2',
                        'hostname': 'test-phone', 'wire_type': '5G'}

        class Router(TplinkRouterSG):
            def request(self, path, data, **kwargs):
                if path.startswith('admin/status?'):
                    return {'lan_macaddr': '02:00:00:00:00:01',
                            'access_devices_wireless_host': ([primary_host] if primary else [])}
                if path.startswith('admin/smart_network?'):
                    item = {'mac': '02:00:00:00:00:02', 'ip': '192.0.2.2',
                            'deviceName': 'test-phone', 'deviceTag': '5G'}
                    if uptime is not None:
                        item['onlineTime'] = uptime
                    return [item]
                if path.startswith('admin/wireless?'):
                    return []
                raise ClientException('Unsupported test endpoint')
        return Router('', '').get_status()

    def test_history_only_zero_uptime_is_not_connected(self):
        self.assertEqual(self.status(0).devices, [])

    def test_primary_client_zero_uptime_stays_connected(self):
        self.assertTrue(self.status(0, primary=True).devices[0].active)

    def test_positive_or_missing_uptime_preserves_smart_only_clients(self):
        for uptime in (45, None):
            with self.subTest(uptime=uptime):
                self.assertTrue(self.status(uptime).devices[0].active)


if __name__ == '__main__':
    unittest.main()
