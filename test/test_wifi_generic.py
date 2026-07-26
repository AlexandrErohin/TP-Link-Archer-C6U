import json
from unittest import main, TestCase
from unittest.mock import patch, Mock
from tplinkrouterc6u import TplinkRouter, Connection, WifiStatus


class TestWifiGeneric(TestCase):
    def setUp(self):
        self.host = 'http://192.168.0.1'
        self.password = 'test_password'
        self.client = TplinkRouter(self.host, self.password)
        self.client._logged = True
        self.client._stok = 'mock_stok'

    @patch('tplinkrouterc6u.client.c6u.post')
    def test_get_wifi(self, mock_post):
        # Test generic Wi-Fi info retrieval for Guest 2G
        mock_data = {
            'enable': 'on',
            'ssid': 'Generic_Guest',
            'encryption': 'portal',
            'portal_password': 'password123'
        }
        
        with patch.object(self.client, 'request', return_value=mock_data):
            info = self.client.get_wifi(Connection.GUEST_2G)

        self.assertIsInstance(info, WifiStatus)
        self.assertTrue(info.enable)
        self.assertEqual(info.ssid, 'Generic_Guest')
        self.assertEqual(info.portal_password, 'password123')

    @patch('tplinkrouterc6u.client.c6u.post')
    def test_get_wifi_prefixed(self, mock_post):
        # Test handling of prefixed keys (e.g. from 'all' form)
        mock_data = {
            'wireless_2g_enable': 'on',
            'wireless_2g_ssid': 'Host_2G'
        }
        
        with patch.object(self.client, 'request', return_value=mock_data):
            info = self.client.get_wifi(Connection.HOST_2G)

        self.assertTrue(info.enable)
        self.assertEqual(info.ssid, 'Host_2G')

    @patch('tplinkrouterc6u.client.c6u.post')
    def test_set_wifi_enhanced(self, mock_post):
        # Verify set_wifi still builds correct data strings
        with patch.object(self.client, 'request') as mock_request:
            self.client.set_wifi(
                wifi=Connection.GUEST_2G,
                ssid='New_SSID',
                portal_password='new_pw'
            )

        args, data = mock_request.call_args[0]
        self.assertIn('guest_2g_ssid=New_SSID', data)
        self.assertIn('guest_2g_portal_password=new_pw', data)
        self.assertIn('form=guest_2g', args)


if __name__ == '__main__':
    main()
