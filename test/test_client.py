import unittest
import macaddress
import ipaddress
import json
from tplinkrouterc6u import (
    TplinkRouter,
    Wifi,
    Status,
    Device,
)


class TestTPLinkClient(unittest.TestCase):
    def test_get_status(self) -> None:
        response_status = '''
{
    "success": true,
    "data": {
        "wireless_2g_wep_format3": "hex",
        "wireless_5g_disabled": "off",
        "wireless_5g_wep_type2": "64",
        "storage_available_unit": "B",
        "storage_vendor": "",
        "usb_storages": {},
        "storage_available": 0,
        "printer_count": 0,
        "printer_name": "None",
        "wan_ipv4_netmask": "255.255.255.0",
        "storage_capacity": 0,
        "access_devices_wired": [
            {
                "wire_type": "wired",
                "macaddr": "3d:24:25:24:30:79",
                "ipaddr": "192.168.1.228",
                "hostname": "SERVER"
            },
            {
                "wire_type": "wired",
                "macaddr": "ac:04:d6:25:2a:96",
                "ipaddr": "192.168.1.254",
                "hostname": "UNKNOWN"
            }
        ],
        "wireless_2g_wds_status": "disable",
        "wireless_2g_wep_type3": "64",
        "wireless_2g_wep_format2": "hex",
        "wan_ipv6_conntype": "none",
        "mem_usage": 0.43,
        "access_devices_wireless_host": [
            {
                "wire_type": "2.4G",
                "macaddr": "06:82:9d:2b:8f:c6",
                "ipaddr": "192.168.1.186",
                "hostname": "UNKNOWN"
            }
        ],
        "guest_5g_psk_key": "",
        "cpu_usage": 0.28,
        "guest_2g_encryption": "none",
        "wireless_5g_encryption": "psk",
        "guest_5g_ssid": "TP-Link_Guest_21CC_5G",
        "guest_5g_hidden": "off",
        "guest_access": "off",
        "wireless_2g_txpower": "high",
        "guest_5g_enable": "off",
        "wireless_2g_macaddr": "macaddr",
        "wireless_5g_disabled_all": "off",
        "guest_5g_extinfo": {
            "support_wds_show": "no",
            "support_band": "both"
        },
        "wireless_5g_current_channel": "48",
        "wireless_2g_port": "1812",
        "wireless_2g_wpa_cipher": "auto",
        "wireless_5g_wep_key4": "",
        "wireless_2g_htmode": "40",
        "guest_5g_encryption": "none",
        "wireless_2g_wep_key3": "",
        "wireless_5g_psk_cipher": "auto",
        "guest_2g_psk_cipher": "aes",
        "wireless_5g_wep_format1": "hex",
        "wireless_2g_wep_select": "1",
        "wireless_2g_wep_type2": "64",
        "wireless_5g_wep_select": "1",
        "wireless_2g_psk_key": "password",
        "wireless_2g_wep_type1": "64",
        "wireless_5g_ssid": "ssid_5Ghz",
        "wireless_2g_wep_key1": "",
        "wireless_2g_current_channel": "1",
        "wan_ipv4_snddns": "8.8.8.8",
        "wan_ipv6_ip6addr": "::",
        "wireless_5g_extinfo": {
            "support_wds_show": "no",
            "support_band": "both"
        },
        "guest_2g_hidden": "off",
        "wireless_2g_channel": "1",
        "wireless_2g_enable": "on",
        "wireless_2g_extinfo": {
            "support_wds_show": "no",
            "support_band": "both"
        },
        "wireless_2g_wpa_version": "auto",
        "wireless_5g_psk_key": "password",
        "wireless_2g_wep_format4": "hex",
        "lan_ipv4_netmask": "255.255.255.0",
        "wireless_5g_wep_key2": "",
        "wireless_5g_enable": "on",
        "wireless_5g_wep_type1": "64",
        "wireless_5g_wep_key1": "",
        "lan_macaddr": "06:e6:97:9e:23:f5",
        "wireless_2g_encryption": "psk",
        "wireless_2g_psk_cipher": "auto",
        "wireless_5g_port": "1812",
        "guest_2g_psk_version": "rsn",
        "wireless_5g_wpa_cipher": "auto",
        "guest_5g_disabled": "off",
        "wireless_5g_hwmode": "anac_5",
        "wan_ipv6_gateway": "::",
        "lan_ipv6_link_local_addr": "FE80::1E3B:F3FF:FE30:21CC/64",
        "wireless_5g_wep_type4": "64",
        "wireless_5g_wep_format4": "hex",
        "wan_ipv6_snddns": "::",
        "wireless_2g_disabled": "off",
        "wireless_5g_wep_format3": "hex",
        "wan_ipv6_pridns": "::",
        "wireless_2g_hidden": "off",
        "wireless_2g_psk_version": "auto",
        "guest_isolate": "off",
        "wan_macaddr": "d6:0b:40:57:da:60",
        "wireless_5g_wps_state": "configured",
        "wireless_2g_wps_state": "configured",
        "wireless_5g_hidden": "off",
        "wireless_5g_psk_version": "auto",
        "wireless_5g_wep_format2": "hex",
        "wireless_2g_ssid": "ssid_2.4Ghz",
        "wireless_2g_wep_key4": "",
        "wireless_5g_wep_mode": "auto",
        "wan_ipv4_ipaddr": "192.168.1.100",
        "guest_2g_extinfo": {
            "support_wds_show": "no",
            "support_band": "both"
        },
        "lan_ipv6_assign_type": "slaac",
        "wireless_2g_wep_format1": "hex",
        "wireless_2g_wep_key2": "",
        "lan_ipv6_ipaddr": "FE80::1E3B:F3FF:FE30:21CC/64",
        "wireless_2g_server": "",
        "wireless_5g_htmode": "80",
        "guest_5g_psk_cipher": "aes",
        "guest_2g_disabled": "off",
        "wan_ipv4_gateway": "192.168.1.254",
        "wireless_2g_disabled_all": "off",
        "guest_2g_psk_key": "",
        "wireless_5g_wpa_key": "",
        "guest_5g_psk_version": "rsn",
        "guest_2g_ssid": "TP-Link_Guest_21CC",
        "wireless_2g_wpa_key": "",
        "wireless_5g_server": "",
        "wireless_5g_macaddr": "macaddr",
        "lan_ipv4_dhcp_enable": "Off",
        "wireless_5g_txpower": "high",
        "wireless_2g_wep_type4": "64",
        "wireless_2g_hwmode": "bgn",
        "wireless_5g_channel": "48",
        "wan_ipv6_enable": "on",
        "wan_ipv4_pridns": "192.168.1.254",
        "guest_2g_enable": "off",
        "wireless_5g_wep_key3": "",
        "wireless_2g_wep_mode": "auto",
        "wireless_5g_wpa_version": "auto",
        "wireless_5g_wep_type3": "64",
        "storage_capacity_unit": "B",
        "wan_ipv4_conntype": "static",
        "lan_ipv4_ipaddr": "192.168.1.100",
        "wireless_5g_wds_status": "disable"
    }
}
        '''
        response_stats = '''
  {
      "data": [
          {
              "mac": "06:82:9d:2b:8f:c6",
              "type": "2.4GHz",
              "encryption": "wpa/wpa2-psk",
              "rxpkts": 4867482,
              "txpkts": 450333
          },
          {
              "mac": "1f:7a:bd:f7:20:0d",
              "type": "5GHz",
              "encryption": "wpa/wpa2-psk",
              "rxpkts": 2953078,
              "txpkts": 134815
          }
      ],
      "timeout": false,
      "success": true,
      "operator": "load"
  }
                '''

        class TPLinkRouterTest(TplinkRouter):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/status?form=all&operation=read':
                    return json.loads(response_status)['data']
                else:
                    return json.loads(response_stats)['data']

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, 'D6-0B-40-57-DA-60')
        self.assertIsInstance(status.wan_macaddress, macaddress.EUI48)
        self.assertEqual(status.lan_macaddr, '06-E6-97-9E-23-F5')
        self.assertIsInstance(status.lan_macaddress, macaddress.EUI48)
        self.assertEqual(status.wan_ipv4_addr, '192.168.1.100')
        self.assertIsInstance(status.lan_ipv4_address, ipaddress.IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.1.100')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.1.254')
        self.assertIsInstance(status.wan_ipv4_address, ipaddress.IPv4Address)
        self.assertEqual(status.wired_total, 2)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 4)
        self.assertEqual(status.guest_2g_enable, False)
        self.assertEqual(status.guest_5g_enable, False)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, True)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertEqual(status.mem_usage, 0.43)
        self.assertEqual(status.cpu_usage, 0.07)
        self.assertEqual(len(status.devices), 2)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Wifi.WIFI_2G)
        self.assertEqual(status.devices[0].macaddr, '06-82-9D-2B-8F-C6')
        self.assertIsInstance(status.devices[0].macaddress, macaddress.EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.1.186')
        self.assertIsInstance(status.devices[0].ipaddress, ipaddress.IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[0].packets_sent, 450333)
        self.assertEqual(status.devices[0].packets_received, 4867482)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Wifi.WIFI_5G)
        self.assertEqual(status.devices[1].macaddr, '1F-7A-BD-F7-20-0D')
        self.assertIsInstance(status.devices[1].macaddress, macaddress.EUI48)
        self.assertEqual(status.devices[1].ipaddr, '0.0.0.0')
        self.assertIsInstance(status.devices[1].ipaddress, ipaddress.IPv4Address)
        self.assertEqual(status.devices[1].hostname, '')
        self.assertEqual(status.devices[1].packets_sent, 134815)
        self.assertEqual(status.devices[1].packets_received, 2953078)

    def test_get_status_ax_55(self) -> None:
        response_status = '''
{
    "success": true,
    "data": {
        "lan_macaddr": "06:e6:97:9e:23:f5",
        "access_devices_wired": [
            {
                "wire_type": "wired",
                "macaddr": "3d:24:25:24:30:79",
                "ipaddr": "192.168.1.228",
                "hostname": "SERVER"
            },
            {
                "wire_type": "wired",
                "macaddr": "ac:04:d6:25:2a:96",
                "ipaddr": "192.168.1.254",
                "hostname": "UNKNOWN"
            }
        ],
        "access_devices_wireless_host": [
            {
                "wire_type": "2.4G",
                "macaddr": "06:82:9d:2b:8f:c6",
                "ipaddr": "192.168.1.186",
                "hostname": "UNKNOWN"
            }
        ],
        "guest_2g_enable": "on",
        "wireless_2g_enable": "on"
    }
}
        '''
        response_stats = '''
  {
      "data": [
          {"mac": "06:82:9d:2b:8f:c6"},
          {"mac": "1f:7a:bd:f7:20:0d"}
      ],
      "timeout": false,
      "success": true,
      "operator": "load"
  }
                '''

        class TPLinkRouterTest(TplinkRouter):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/status?form=all&operation=read':
                    return json.loads(response_status)['data']
                else:
                    return json.loads(response_stats)['data']

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, None)
        self.assertEqual(status.lan_macaddr, '06-E6-97-9E-23-F5')
        self.assertIsInstance(status.lan_macaddress, macaddress.EUI48)
        self.assertEqual(status.wan_ipv4_addr, None)
        self.assertEqual(status.lan_ipv4_addr, None)
        self.assertEqual(status.wan_ipv4_gateway, None)
        self.assertEqual(status.wired_total, 2)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 4)
        self.assertEqual(status.guest_2g_enable, True)
        self.assertEqual(status.guest_5g_enable, None)
        self.assertEqual(status.guest_6g_enable, None)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.iot_6g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, None)
        self.assertEqual(status.wifi_6g_enable, None)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertEqual(status.mem_usage, None)
        self.assertEqual(status.cpu_usage, None)
        self.assertEqual(len(status.devices), 2)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Wifi.WIFI_2G)
        self.assertEqual(status.devices[0].macaddr, '06-82-9D-2B-8F-C6')
        self.assertIsInstance(status.devices[0].macaddress, macaddress.EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.1.186')
        self.assertIsInstance(status.devices[0].ipaddress, ipaddress.IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Wifi.WIFI_UNKNOWN)
        self.assertEqual(status.devices[1].macaddr, '1F-7A-BD-F7-20-0D')
        self.assertIsInstance(status.devices[1].macaddress, macaddress.EUI48)
        self.assertEqual(status.devices[1].ipaddr, '0.0.0.0')
        self.assertIsInstance(status.devices[1].ipaddress, ipaddress.IPv4Address)
        self.assertEqual(status.devices[1].hostname, '')
        self.assertEqual(status.devices[1].packets_sent, None)
        self.assertEqual(status.devices[1].packets_received, None)


if __name__ == '__main__':
    unittest.main()
