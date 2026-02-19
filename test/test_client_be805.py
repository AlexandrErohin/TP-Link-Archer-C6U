
from unittest import TestCase
from unittest.mock import patch, MagicMock
from json import loads
from tplinkrouterc6u.client.be805 import TplinkBE805Client
from tplinkrouterc6u import (
    Status,
    IPv4Status,
    Connection,
    ClientException,
    Firmware
)


class TestTPLinkBE805Client(TestCase):

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_get_firmware(self, mock_request) -> None:
        response = {
            "success": True,
            "data": {
                "upgraded": False,
                "hardware_version": "Archer BE805 v1.20",
                "model": "Archer BE805",
                "upgradetime": 16,
                "totaltime": 115,
                "is_default": False,
                "firmware_version": "1.2.2 Build 20250424 rel.45837(5347)"
            }
        }
        mock_request.return_value = response['data']

        client = TplinkBE805Client('192.168.1.1', 'password')
        # We need to bypass __init__ logic that might call request or setup things? 
        # Actually __init__ is fine, it just sets variables. 
        # But we need to mock other things potentially? No, just request.
        
        firmware = client.get_firmware()

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, "Archer BE805 v1.20")
        
        # Verify URL modification: generic handler should handle it.
        # But wait, get_firmware in base class calls: request(self._url_firmware, 'operation=read')
        # And in BE805 __init__, we removed the override, so it uses default: 'admin/firmware?form=upgrade'
        # So request is called with: path='admin/firmware?form=upgrade', data='operation=read'
        # BE805.request should change path to: 'admin/firmware?form=upgrade&operation=read'
        

        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        self.assertEqual(args[0], 'admin/firmware?form=upgrade&operation=read')
        self.assertIn('"operation": "read"', args[1])

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_get_ipv4_status(self, mock_request) -> None:
        response = {
            "success": True,
            "data": {
                "lan_ipv4_dhcp_enable": "On",
                "lan_macaddr": "0C-EF-15-51-AD-82",
                "wan_ipv4_snddns": "8.8.4.4",
                "wan_macaddr": "0C-EF-15-51-AD-83",
                "wan_ipv4_pridns": "8.8.8.8",
                "wan_ipv4_gateway": "175.156.192.1",
                "wan_ipv4_conntype": "dhcp",
                "wan_ipv4_netmask": "255.255.224.0",
                "lan_ipv4_netmask": "255.255.255.0",
                "wan_ipv4_ipaddr": "175.156.194.150",
                "wan_ipv4_uptime": 73,
                "lan_ipv4_ipaddr": "192.168.1.1"
            }
        }
        mock_request.return_value = response['data']

        client = TplinkBE805Client('192.168.1.1', 'p')
        status = client.get_ipv4_status()

        self.assertIsInstance(status, IPv4Status)
        self.assertEqual(str(status.wan_ipv4_ipaddr), "175.156.194.150")
        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        self.assertEqual(args[0], 'admin/network?form=status_ipv4&operation=read')
        self.assertIn('"operation": "read"', args[1])

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_set_wifi(self, mock_request) -> None:
        client = TplinkBE805Client('1.1.1.1', 'p')
        client.set_wifi(Connection.GUEST_2G, True)
        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        
        path = args[0]
        data = args[1]
        
        self.assertTrue('operation=write' in path)
        self.assertTrue('admin/wireless' in path)
        data_json = loads(data)
        self.assertEqual(data_json.get('operation'), 'write')
        self.assertEqual(data_json.get('guest_2g_enable'), 'on')

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_reboot(self, mock_request) -> None:
        client = TplinkBE805Client('1.1', 'p')
        client.reboot()
        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        path = args[0]
        data = args[1]
        
        self.assertEqual(path, 'admin/system?form=reboot&operation=write')
        data_json = loads(data)
        self.assertEqual(data_json.get('operation'), 'write')
