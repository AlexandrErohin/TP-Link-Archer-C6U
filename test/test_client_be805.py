
from unittest import TestCase
from unittest.mock import patch, MagicMock
from json import loads
from tplinkrouterc6u.client.be805 import TplinkBE805Client
from tplinkrouterc6u import (
    Status,
    IPv4Status,
    Connection,
    ClientException,
    Firmware,
    IPv4Reservation,
    IPv4DHCPLease
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
        firmware = client.get_firmware()

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, "Archer BE805 v1.20")
        
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
        client = TplinkBE805Client('192.168.1.1', 'p')
        client.set_wifi(Connection.GUEST_2G, True)
        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        
        path = args[0]
        data = args[1]
        
        self.assertTrue('operation=write' in path)
        self.assertTrue('admin/wireless' in path)
        data_json = loads(data)
        self.assertEqual(data_json.get('operation'), 'write')
        self.assertEqual(data_json.get('enable'), 'on')

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_reboot(self, mock_request) -> None:
        client = TplinkBE805Client('192.168.1.1', 'p')
        client.reboot()
        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        path = args[0]
        data = args[1]
        
        self.assertEqual(path, 'admin/system?form=reboot&operation=write')
        data_json = loads(data)
        self.assertEqual(data_json.get('operation'), 'write')

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_get_status(self, mock_request) -> None:
        status_data = {
            "wan_macaddr": "0C-EF-15-51-AD-83",
            "lan_macaddr": "0C-EF-15-51-AD-82",
            "wan_ipv4_ipaddr": "175.156.194.150",
            "lan_ipv4_ipaddr": "192.168.1.1",
            "wan_ipv4_gateway": "175.156.192.1",
            "wan_ipv4_uptime": 73,
            "mem_usage": "0.45",
            "cpu_usage": "0.12",
            "conn_type": "dhcp",
            "access_devices_wired": [],
            "access_devices_wireless_host": [],
            "access_devices_wireless_guest": [],
        }

        def side_effect(path, data, *args, **kwargs):
            if 'admin/status?form=all' in path:
                return status_data
            if 'admin/smart_network' in path:
                return []
            if 'admin/wireless?form=statistics' in path:
                return []
            if 'admin/status?form=perf' in path:
                return {}
            return {}

        mock_request.side_effect = side_effect

        client = TplinkBE805Client('192.168.1.1', 'p')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(str(status.wan_ipv4_addr), "175.156.194.150")
        
        # Verify the main call was made
        # We can't simple check call_args because multiple calls happened
        # We check if *any* call matches our expectation
        found_status_call = False
        for call_args in mock_request.call_args_list:
            args, _ = call_args
            if 'admin/status?form=all&operation=read' in args[0]:
                found_status_call = True
                data_json = loads(args[1])
                self.assertEqual(data_json.get('operation'), 'read')
                break
        self.assertTrue(found_status_call)

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_get_ipv4_reservations(self, mock_request) -> None:
        response = [
            {
                "mac": "AA-BB-CC-DD-EE-FF",
                "ip": "192.168.1.100",
                "comment": "Test Device",
                "enable": "on"
            }
        ]
        mock_request.return_value = response

        client = TplinkBE805Client('192.168.1.1', 'p')
        reservations = client.get_ipv4_reservations()

        self.assertEqual(len(reservations), 1)
        self.assertIsInstance(reservations[0], IPv4Reservation)
        self.assertEqual(str(reservations[0].macaddr), "AA-BB-CC-DD-EE-FF")
        self.assertEqual(str(reservations[0].ipaddr), "192.168.1.100")
        self.assertTrue(reservations[0].enabled)
        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        # checking default URL from base class
        self.assertEqual(args[0], 'admin/dhcps?form=reservation&operation=load')
        data_json = loads(args[1])
        self.assertEqual(data_json.get('operation'), 'load')

    @patch('tplinkrouterc6u.client.c6u.TplinkRouter.request')
    def test_get_ipv4_dhcp_leases(self, mock_request) -> None:
        response = [
            {
                "macaddr": "AA-BB-CC-DD-EE-AA",
                "ipaddr": "192.168.1.101",
                "name": "Leased Device",
                "leasetime": "120"
            }
        ]
        mock_request.return_value = response

        client = TplinkBE805Client('192.168.1.1', 'p')
        leases = client.get_ipv4_dhcp_leases()

        self.assertEqual(len(leases), 1)
        self.assertIsInstance(leases[0], IPv4DHCPLease)
        self.assertEqual(str(leases[0].macaddr), "AA-BB-CC-DD-EE-AA")
        self.assertEqual(str(leases[0].ipaddr), "192.168.1.101")
        self.assertEqual(leases[0].hostname, "Leased Device")
        
        mock_request.assert_called()
        args, _ = mock_request.call_args
        # checking default URL from base class
        self.assertEqual(args[0], 'admin/dhcps?form=client&operation=load')
        data_json = loads(args[1])
        self.assertEqual(data_json.get('operation'), 'load')
