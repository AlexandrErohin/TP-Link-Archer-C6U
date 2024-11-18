import json
from ipaddress import IPv4Address
from unittest import TestCase, main

from macaddress import EUI48

from tplinkrouterc6u import IPv4Status
from tplinkrouterc6u.client.xdr import TPLinkXDRClient
from tplinkrouterc6u.common.dataclass import (Device, Firmware, IPv4DHCPLease,
                                              IPv4Reservation, Status)
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


class TestTPLinkXDRClient(TestCase):
    def test_logout(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        client.logout()

        self.assertEqual(check_payload['method'], 'do')
        self.assertIn('system', check_payload)
        self.assertIn('logout', check_payload['system'])
        self.assertEqual(check_payload['system']['logout'], None)

    def test_get_firmware(self) -> None:
        mock_data = json.loads('''
{
  "device_info": {
    "info": {
      "sys_software_revision": "1342242834",
      "sys_software_revision_minor": "0",
      "device_name": "TP-LINK Wireless Router TL-XDR3010\u6613\u5c55\u7248",
      "device_info": "XDR3010\u6613\u5c55\u7248V2 Wireless Router",
      "device_model": "TL-XDR3010\u6613\u5c55\u7248",
      "hw_version": "TL-XDR3010\u6613\u5c55\u7248 2.0",
      "domain_name": "tplogin.cn",
      "language": "CN",
      "product_id": "806395938",
      "vendor_id": "0",
      "sw_version": "1.0.18 Build 220711 Rel.56168n",
      "enable_dns": "1"
    }
  },
  "error_code": 0
}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        firmware = client.get_firmware()

        self.assertEqual(check_payload['method'], 'get')
        self.assertIn('device_info', check_payload)
        self.assertIn('name', check_payload['device_info'])
        self.assertEqual(check_payload['device_info']['name'], 'info')

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.firmware_version, '1.0.18 Build 220711 Rel.56168n')
        self.assertEqual(firmware.hardware_version, 'TL-XDR3010易展版 2.0')
        self.assertEqual(firmware.model, 'TL-XDR3010易展版')

    def test_get_status(self) -> None:
        mock_data = json.loads('''{
  "hosts_info": {
    "host_info": [
      {
        "host_info_5": {
          "mac": "b8-27-eb-0e-87-eb",
          "parent_mac": "ec-60-73-2b-0b-ee",
          "is_mesh": "0",
          "wifi_mode": "0",
          "type": "0",
          "blocked": "0",
          "ip": "192.168.1.200",
          "hostname": "raspberrypi",
          "up_speed": "0",
          "down_speed": "0",
          "up_limit": "0",
          "down_limit": "0",
          "is_cur_host": "1",
          "ssid": "",
          "forbid_domain": "",
          "limit_time": "",
          "plan_rule": []
        }
      },
      {
        "host_info_3": {
          "mac": "24-59-e5-d0-21-8c",
          "parent_mac": "ec-60-73-2b-0b-ee",
          "is_mesh": "0",
          "wifi_mode": "0",
          "type": "1",
          "blocked": "0",
          "ip": "192.168.1.201",
          "hostname": "midea%5Fac%5F0361",
          "up_speed": "0",
          "down_speed": "0",
          "up_limit": "0",
          "down_limit": "0",
          "is_cur_host": "0",
          "ssid": "",
          "forbid_domain": "",
          "limit_time": "",
          "plan_rule": []
        }
      }
    ]
  },
  "network": {
    "wan_status": {
      "ipaddr": "0.0.0.0",
      "netmask": "0.0.0.0",
      "gateway": "0.0.0.0",
      "pri_dns": "0.0.0.0",
      "snd_dns": "0.0.0.0",
      "link_status": 0,
      "error_code": 4,
      "proto": "dhcp",
      "up_time": 0,
      "up_speed": 0,
      "down_speed": 0,
      "phy_status": 0
    },
    "lan": {
      "ipaddr": "192.168.1.100",
      "netmask": "255.255.255.0",
      "ip_mode": "dynamic",
      "fac_ipaddr": "192.168.1.1",
      "fac_netmask": "255.255.255.0",
      "macaddr": "ec-60-73-2b-0b-ee"
    }
  },
  "wireless": {
    "wlan_bs": {
      "wifi_enable": "1",
      "bs_enable": "1",
      "ssid": "tx",
      "ssidbrd": "1",
      "encryption": "1",
      "key": "123654789a.",
      "auth": "0",
      "cipher": "1"
    },
    "wlan_host_2g": {
      "enable": "1",
      "ssid": "tx",
      "ssidbrd": "1",
      "encryption": "1",
      "key": "123654789a.",
      "channel": "0",
      "mode": "9",
      "bandwidth": "1",
      "power": "0",
      "isolate": "0",
      "turboon": "0",
      "auth": "0",
      "cipher": "1",
      "twt": "0",
      "ofdma": "1"
    },
    "wlan_wds_2g": {
      "enable": "0",
      "ssid": "",
      "bssid": "00-00-00-00-00-00",
      "encryption": "0",
      "key": "",
      "address_form": "0",
      "in_wizard": "0"
    },
    "wlan_host_5g": {
      "enable": "0",
      "ssid": "TP-LINK_5G_0BEE",
      "ssidbrd": "1",
      "encryption": "0",
      "key": "",
      "channel": "0",
      "mode": "10",
      "bandwidth": "0",
      "power": "0",
      "isolate": "0",
      "turboon": "0",
      "auth": "0",
      "cipher": "1",
      "twt": "1",
      "ofdma": "1"
    },
    "wlan_wds_5g": {
      "enable": "0",
      "ssid": "",
      "bssid": "00-00-00-00-00-00",
      "encryption": "0",
      "key": "",
      "address_form": "0",
      "in_wizard": "0"
    }
  },
  "guest_network": {
    "guest_2g": {
      "ssid": "TPGuest%5F0BEE",
      "encrypt": "0",
      "key": "",
      "enable": "0",
      "accright": "0",
      "upload": "0",
      "download": "0",
      "time_limit": "0",
      "limit_type": "timeout",
      "duration": "0",
      "auth": "0",
      "cipher": "1"
    }
  },
  "error_code": 0
}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        status = client.get_status()

        self.assertEqual(check_payload['method'], 'get')
        self.assertEqual(check_payload['hosts_info']['table'], 'host_info')
        self.assertIn('network', check_payload)
        self.assertIn('name', check_payload['network'])
        self.assertEqual(check_payload['network']['name'], ['wan_status', 'lan'])
        self.assertIn('wireless', check_payload)
        self.assertIn('name', check_payload['wireless'])
        self.assertEqual(check_payload['wireless']['name'], [
            'wlan_bs',
            'wlan_host_2g',
            'wlan_wds_2g',
            'wlan_host_5g',
            'wlan_wds_5g',
        ])
        self.assertIn('guest_network', check_payload)
        self.assertIn('name', check_payload['guest_network'])
        self.assertEqual(check_payload['guest_network']['name'], ['guest_2g'])

        self.assertIsInstance(status, Status)
        self.assertEqual(status.lan_ipv4_addr, '192.168.1.100')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_macaddr, 'EC-60-73-2B-0B-EE')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '0.0.0.0')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertEqual(len(status.devices), 2)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.WIRED)
        self.assertEqual(status.devices[0].macaddr, 'B8-27-EB-0E-87-EB')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.1.200')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'raspberrypi')
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.HOST_2G)
        self.assertEqual(status.devices[1].macaddr, '24-59-E5-D0-21-8C')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.1.201')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'midea_ac_0361')

    def test_reboot(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        client.reboot()

        self.assertEqual(check_payload['method'], 'do')
        self.assertIn('system', check_payload)
        self.assertIn('reboot', check_payload['system'])
        self.assertEqual(check_payload['system']['reboot'], None)

    def test_set_wifi_enable_guest_2g(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        client.set_wifi(Connection.GUEST_2G, True)

        self.assertEqual(check_payload['method'], 'set')
        self.assertIn('guest_network', check_payload)
        self.assertIn('guest_2g', check_payload['guest_network'])
        self.assertEqual(check_payload['guest_network']['guest_2g']['enable'], '1')

    def test_set_wifi_enable_host_2g(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        client.set_wifi(Connection.HOST_2G, True)

        self.assertEqual(check_payload['method'], 'set')
        self.assertIn('wireless', check_payload)
        self.assertIn('wlan_host_2g', check_payload['wireless'])
        self.assertEqual(check_payload['wireless']['wlan_host_2g']['enable'], 1)

    def test_set_wifi_disable_host_5g(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        client.set_wifi(Connection.HOST_5G, False)

        self.assertEqual(check_payload['method'], 'set')
        self.assertIn('wireless', check_payload)
        self.assertIn('wlan_host_5g', check_payload['wireless'])
        self.assertEqual(check_payload['wireless']['wlan_host_5g']['enable'], 0)

    def test_get_ipv4_reservations(self):
        mock_data = json.loads('''{
"ip_mac_bind": {
    "user_bind": [{"user_bind_3": {"mac": "24-59-E5-D0-21-8C", "ip": "192.168.2.202", "hostname": "midea_ac_0361"}}]
},
"error_code": 0}
''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        reservations = client.get_ipv4_reservations()

        self.assertEqual(check_payload['method'], 'get')
        self.assertIsInstance(check_payload['ip_mac_bind'], dict)
        self.assertEqual(check_payload['ip_mac_bind']['table'], 'user_bind')

        self.assertEqual(len(reservations), 1)
        self.assertIsInstance(reservations[0], IPv4Reservation)
        self.assertEqual(reservations[0].macaddr, '24-59-E5-D0-21-8C')
        self.assertIsInstance(reservations[0].macaddress, EUI48)
        self.assertEqual(reservations[0].macaddress, get_mac('24-59-E5-D0-21-8C'))
        self.assertEqual(reservations[0].ipaddr, '192.168.2.202')
        self.assertIsInstance(reservations[0].ipaddress, IPv4Address)
        self.assertEqual(reservations[0].ipaddress, get_ip('192.168.2.202'))
        self.assertEqual(reservations[0].hostname, 'midea_ac_0361')

    def test_get_ipv4_dhcp_leases(self):
        mock_data = json.loads('''
{
  "dhcpd": {
    "dhcp_clients": [
      {
        "dhcp_client_1": {
          "mac": "24-59-e5-d0-21-8c",
          "ip": "192.168.2.202",
          "hostname": "midea_ac_0361",
          "expires": "4294967295"
        }
      },
      {
        "dhcp_client_2": {
          "mac": "b8-27-eb-0e-87-eb",
          "ip": "192.168.2.200",
          "hostname": "raspberrypi",
          "expires": "3200"
        }
      }
    ]
  },
  "error_code": 0
}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        dhcp_leases = client.get_ipv4_dhcp_leases()

        self.assertEqual(check_payload['method'], 'get')
        self.assertIsInstance(check_payload['dhcpd'], dict)
        self.assertEqual(check_payload['dhcpd']['table'], 'dhcp_clients')

        self.assertEqual(len(dhcp_leases), 2)
        self.assertIsInstance(dhcp_leases[0], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[0].macaddr, '24-59-E5-D0-21-8C')
        self.assertIsInstance(dhcp_leases[0].macaddress, EUI48)
        self.assertEqual(dhcp_leases[0].macaddress, get_mac('24-59-e5-d0-21-8c'))
        self.assertEqual(dhcp_leases[0].ipaddr, '192.168.2.202')
        self.assertIsInstance(dhcp_leases[0].ipaddress, IPv4Address)
        self.assertEqual(dhcp_leases[0].ipaddress, get_ip('192.168.2.202'))
        self.assertEqual(dhcp_leases[0].hostname, 'midea_ac_0361')
        self.assertEqual(dhcp_leases[0].lease_time, 'Permanent')
        self.assertIsInstance(dhcp_leases[1], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[1].macaddr, 'B8-27-EB-0E-87-EB')
        self.assertIsInstance(dhcp_leases[1].macaddress, EUI48)
        self.assertEqual(dhcp_leases[1].macaddress, get_mac('b8-27-eb-0e-87-eb'))
        self.assertEqual(dhcp_leases[1].ipaddr, '192.168.2.200')
        self.assertIsInstance(dhcp_leases[1].ipaddress, IPv4Address)
        self.assertEqual(dhcp_leases[1].ipaddress, get_ip('192.168.2.200'))
        self.assertEqual(dhcp_leases[1].hostname, 'raspberrypi')
        self.assertEqual(dhcp_leases[1].lease_time, '0:53:20')

    def test_get_ipv4_status(self):
        mock_data = json.loads('''
{
  "dhcpd": {
    "udhcpd": {
      "auto": "1",
      "enable": "0",
      "pool_start": "192.168.1.2",
      "pool_end": "192.168.1.254",
      "lease_time": "7200",
      "pri_dns": "211.136.192.6",
      "snd_dns": "0.0.0.0",
      "gateway": "192.168.2.1",
      "pool_extend": "1"
    }
  },
  "network": {
    "lan": {
      "ipaddr": "192.168.1.100",
      "netmask": "255.255.255.0",
      "ip_mode": "dynamic",
      "fac_ipaddr": "192.168.1.1",
      "fac_netmask": "255.255.255.0",
      "macaddr": "ec-60-73-2b-0b-ee"
    },
    "wan_status": {
      "ipaddr": "0.0.0.0",
      "netmask": "0.0.0.0",
      "gateway": "0.0.0.0",
      "pri_dns": "0.0.0.0",
      "snd_dns": "0.0.0.0",
      "link_status": 0,
      "error_code": 4,
      "proto": "dhcp",
      "up_time": 0,
      "up_speed": 0,
      "down_speed": 0,
      "phy_status": 0
    }
  },
  "error_code": 0
}''')
        check_payload = {}

        class TPLinkXDRClientTest(TPLinkXDRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkXDRClientTest('', '')
        ipv4_status = client.get_ipv4_status()

        self.assertEqual(check_payload['method'], 'get')
        self.assertIsInstance(check_payload['dhcpd'], dict)
        self.assertEqual(check_payload['dhcpd']['name'], 'udhcpd')
        self.assertIsInstance(check_payload['network'], dict)
        self.assertEqual(check_payload['network']['name'], ['lan', 'wan_status'])

        self.assertIsInstance(ipv4_status, IPv4Status)
        self.assertEqual(ipv4_status.wan_ipv4_ipaddr, '0.0.0.0')
        self.assertIsInstance(ipv4_status.wan_ipv4_ipaddress, IPv4Address)
        self.assertEqual(ipv4_status.wan_ipv4_ipaddress, get_ip('0.0.0.0'))
        self.assertEqual(ipv4_status.wan_ipv4_gateway, '0.0.0.0')
        self.assertIsInstance(ipv4_status.wan_ipv4_gateway_address, IPv4Address)
        self.assertEqual(ipv4_status.wan_ipv4_gateway_address, get_ip('0.0.0.0'))
        self.assertEqual(ipv4_status.wan_ipv4_netmask, '0.0.0.0')
        self.assertIsInstance(ipv4_status.wan_ipv4_netmask_address, IPv4Address)
        self.assertEqual(ipv4_status.wan_ipv4_netmask_address, get_ip('0.0.0.0'))
        self.assertEqual(ipv4_status.wan_ipv4_pridns, '0.0.0.0')
        self.assertIsInstance(ipv4_status.wan_ipv4_pridns_address, IPv4Address)
        self.assertEqual(ipv4_status.wan_ipv4_pridns_address, get_ip('0.0.0.0'))
        self.assertEqual(ipv4_status.wan_ipv4_snddns, '0.0.0.0')
        self.assertIsInstance(ipv4_status.wan_ipv4_snddns_address, IPv4Address)
        self.assertEqual(ipv4_status.wan_ipv4_snddns_address, get_ip('0.0.0.0'))
        self.assertEqual(ipv4_status.lan_macaddr, 'EC-60-73-2B-0B-EE')
        self.assertIsInstance(ipv4_status.lan_macaddress, EUI48)
        self.assertEqual(ipv4_status.lan_macaddress, get_mac('EC-60-73-2B-0B-EE'))
        self.assertEqual(ipv4_status.lan_ipv4_ipaddr, '192.168.1.100')
        self.assertIsInstance(ipv4_status.lan_ipv4_ipaddress, IPv4Address)
        self.assertEqual(ipv4_status.lan_ipv4_ipaddress, get_ip('192.168.1.100'))
        self.assertEqual(ipv4_status.lan_ipv4_dhcp_enable, False)
        self.assertEqual(ipv4_status.lan_ipv4_netmask, '255.255.255.0')
        self.assertIsInstance(ipv4_status.lan_ipv4_netmask_address, IPv4Address)
        self.assertEqual(ipv4_status.lan_ipv4_netmask_address, get_ip('255.255.255.0'))


if __name__ == '__main__':
    main()
