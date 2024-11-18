from unittest import main, TestCase
from macaddress import EUI48
from ipaddress import IPv4Address
from json import loads
from tplinkrouterc6u import (
    TplinkRouter,
    Connection,
    Status,
    Device,
    ClientException,
)


class TestTPLinkClient(TestCase):
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
            },
            {
                "wire_type": "2.4G",
                "macaddr": "06:55:9d:2b:8f:a7",
                "ipaddr": "Unknown",
                "hostname": "Unknown"
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
                    return loads(response_status)['data']
                elif path == 'admin/wireless?form=statistics':
                    return loads(response_stats)['data']
                raise ClientException()

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, 'D6-0B-40-57-DA-60')
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, '06-E6-97-9E-23-F5')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '192.168.1.100')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.1.100')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.1.254')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertEqual(status.wired_total, 2)
        self.assertEqual(status.wifi_clients_total, 3)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 5)
        self.assertEqual(status.iot_clients_total, None)
        self.assertEqual(status.guest_2g_enable, False)
        self.assertEqual(status.guest_5g_enable, False)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, True)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertEqual(status.mem_usage, 0.43)
        self.assertEqual(status.cpu_usage, 0.28)
        self.assertEqual(len(status.devices), 5)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.WIRED)
        self.assertEqual(status.devices[0].macaddr, '3D-24-25-24-30-79')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.1.228')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'SERVER')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[1].type, Connection.WIRED)
        self.assertEqual(status.devices[1].macaddr, 'AC-04-D6-25-2A-96')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.1.254')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[1].packets_sent, None)
        self.assertEqual(status.devices[1].packets_received, None)
        self.assertIsInstance(status.devices[2], Device)
        self.assertEqual(status.devices[2].type, Connection.HOST_2G)
        self.assertEqual(status.devices[2].macaddr, '06-82-9D-2B-8F-C6')
        self.assertEqual(status.devices[2].ipaddr, '192.168.1.186')
        self.assertEqual(status.devices[2].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[2].packets_sent, 450333)
        self.assertEqual(status.devices[2].packets_received, 4867482)
        self.assertIsInstance(status.devices[3], Device)
        self.assertEqual(status.devices[3].type, Connection.HOST_2G)
        self.assertEqual(status.devices[3].macaddr, '06-55-9D-2B-8F-A7')
        self.assertEqual(status.devices[3].ipaddr, '0.0.0.0')
        self.assertEqual(status.devices[3].hostname, 'Unknown')
        self.assertEqual(status.devices[3].packets_sent, None)
        self.assertEqual(status.devices[3].packets_received, None)
        self.assertIsInstance(status.devices[4], Device)
        self.assertEqual(status.devices[4].type, Connection.HOST_5G)
        self.assertEqual(status.devices[4].macaddr, '1F-7A-BD-F7-20-0D')
        self.assertEqual(status.devices[4].ipaddr, '0.0.0.0')
        self.assertEqual(status.devices[4].hostname, '')
        self.assertEqual(status.devices[4].packets_sent, 134815)
        self.assertEqual(status.devices[4].packets_received, 2953078)

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
                    return loads(response_status)['data']
                elif path == 'admin/wireless?form=statistics':
                    return loads(response_stats)['data']
                raise ClientException()

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, None)
        self.assertEqual(status.lan_macaddr, '06-E6-97-9E-23-F5')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, None)
        self.assertEqual(status.lan_ipv4_addr, None)
        self.assertEqual(status.wan_ipv4_gateway, None)
        self.assertEqual(status.wired_total, 2)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 4)
        self.assertEqual(status.iot_clients_total, None)
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
        self.assertEqual(len(status.devices), 4)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.WIRED)
        self.assertEqual(status.devices[0].macaddr, '3D-24-25-24-30-79')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.1.228')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'SERVER')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.WIRED)
        self.assertEqual(status.devices[1].macaddr, 'AC-04-D6-25-2A-96')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.1.254')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[1].packets_sent, None)
        self.assertEqual(status.devices[1].packets_received, None)
        self.assertIsInstance(status.devices[2], Device)
        self.assertEqual(status.devices[2].type, Connection.HOST_2G)
        self.assertEqual(status.devices[2].macaddr, '06-82-9D-2B-8F-C6')
        self.assertIsInstance(status.devices[2].macaddress, EUI48)
        self.assertEqual(status.devices[2].ipaddr, '192.168.1.186')
        self.assertIsInstance(status.devices[2].ipaddress, IPv4Address)
        self.assertEqual(status.devices[2].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[2].packets_sent, None)
        self.assertEqual(status.devices[2].packets_received, None)
        self.assertIsInstance(status.devices[3], Device)
        self.assertEqual(status.devices[3].type, Connection.UNKNOWN)
        self.assertEqual(status.devices[3].macaddr, '1F-7A-BD-F7-20-0D')
        self.assertEqual(status.devices[3].ipaddr, '0.0.0.0')
        self.assertEqual(status.devices[3].hostname, '')
        self.assertEqual(status.devices[3].packets_sent, None)
        self.assertEqual(status.devices[3].packets_received, None)

    def test_get_status_with_game_accelerator(self) -> None:
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
        response_game_accelerator = '''
  {
      "data": [
          {"mac": "06:82:9d:2b:8f:c6", "deviceTag":"2.4G", "isGuest":false, "ip":"192.168.1.186",
          "deviceName":"name1", "uploadSpeed":12, "downloadSpeed":77},
          {"mac": "fb:90:b8:2a:8a:b1", "deviceTag":"iot_2.4G", "isGuest":false, "ip":"192.168.1.187",
          "deviceName":"name2"},
          {"mac": "54:b3:a2:f7:be:ea", "deviceTag":"iot_5G", "isGuest":false, "ip":"192.168.1.188",
          "deviceName":"name3"},
          {"mac": "3c:ae:e1:83:94:9d", "deviceTag":"iot_6G", "isGuest":false, "ip":"192.168.1.189",
          "deviceName":"name4", "signal": -52}
      ],
      "timeout": false,
      "success": true
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
                    return loads(response_status)['data']
                elif path == 'admin/smart_network?form=game_accelerator':
                    return loads(response_game_accelerator)['data']
                elif path == 'admin/wireless?form=statistics':
                    return loads(response_stats)['data']
                raise ClientException()

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, None)
        self.assertEqual(status.lan_macaddr, '06-E6-97-9E-23-F5')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, None)
        self.assertEqual(status.lan_ipv4_addr, None)
        self.assertEqual(status.wan_ipv4_gateway, None)
        self.assertEqual(status.wired_total, 2)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 4)
        self.assertEqual(status.iot_clients_total, 3)
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
        self.assertEqual(len(status.devices), 7)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.WIRED)
        self.assertEqual(status.devices[0].macaddr, '3D-24-25-24-30-79')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.1.228')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'SERVER')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.WIRED)
        self.assertEqual(status.devices[1].macaddr, 'AC-04-D6-25-2A-96')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.1.254')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[1].packets_sent, None)
        self.assertEqual(status.devices[1].packets_received, None)
        self.assertIsInstance(status.devices[2], Device)
        self.assertEqual(status.devices[2].type, Connection.HOST_2G)
        self.assertEqual(status.devices[2].macaddr, '06-82-9D-2B-8F-C6')
        self.assertIsInstance(status.devices[2].macaddress, EUI48)
        self.assertEqual(status.devices[2].ipaddr, '192.168.1.186')
        self.assertIsInstance(status.devices[2].ipaddress, IPv4Address)
        self.assertEqual(status.devices[2].hostname, 'UNKNOWN')
        self.assertEqual(status.devices[2].packets_sent, 450333)
        self.assertEqual(status.devices[2].packets_received, 4867482)
        self.assertEqual(status.devices[2].up_speed, 12)
        self.assertEqual(status.devices[2].down_speed, 77)
        self.assertIsInstance(status.devices[3], Device)
        self.assertEqual(status.devices[3].type, Connection.IOT_2G)
        self.assertEqual(status.devices[3].macaddr, 'FB-90-B8-2A-8A-B1')
        self.assertIsInstance(status.devices[3].macaddress, EUI48)
        self.assertEqual(status.devices[3].ipaddr, '192.168.1.187')
        self.assertIsInstance(status.devices[3].ipaddress, IPv4Address)
        self.assertEqual(status.devices[3].hostname, 'name2')
        self.assertEqual(status.devices[3].packets_sent, None)
        self.assertEqual(status.devices[3].packets_received, None)
        self.assertIsInstance(status.devices[4], Device)
        self.assertEqual(status.devices[4].type, Connection.IOT_5G)
        self.assertEqual(status.devices[4].macaddr, '54-B3-A2-F7-BE-EA')
        self.assertIsInstance(status.devices[4].macaddress, EUI48)
        self.assertEqual(status.devices[4].ipaddr, '192.168.1.188')
        self.assertIsInstance(status.devices[4].ipaddress, IPv4Address)
        self.assertEqual(status.devices[4].hostname, 'name3')
        self.assertEqual(status.devices[4].packets_sent, None)
        self.assertEqual(status.devices[4].packets_received, None)
        self.assertIsInstance(status.devices[5], Device)
        self.assertEqual(status.devices[5].type, Connection.IOT_6G)
        self.assertEqual(status.devices[5].macaddr, '3C-AE-E1-83-94-9D')
        self.assertIsInstance(status.devices[5].macaddress, EUI48)
        self.assertEqual(status.devices[5].ipaddr, '192.168.1.189')
        self.assertIsInstance(status.devices[5].ipaddress, IPv4Address)
        self.assertEqual(status.devices[5].hostname, 'name4')
        self.assertEqual(status.devices[5].packets_sent, None)
        self.assertEqual(status.devices[5].packets_received, None)
        self.assertEqual(status.devices[5].signal, -52)
        self.assertIsInstance(status.devices[6], Device)
        self.assertEqual(status.devices[6].type, Connection.HOST_5G)
        self.assertEqual(status.devices[6].macaddr, '1F-7A-BD-F7-20-0D')
        self.assertIsInstance(status.devices[6].macaddress, EUI48)
        self.assertEqual(status.devices[6].ipaddr, '0.0.0.0')
        self.assertIsInstance(status.devices[6].ipaddress, IPv4Address)
        self.assertEqual(status.devices[6].hostname, '')
        self.assertEqual(status.devices[6].packets_sent, 134815)
        self.assertEqual(status.devices[6].packets_received, 2953078)

    def test_get_status_with_perf_request(self) -> None:
        response_status = '''
    {
        "success": true,
        "data": {
            "lan_macaddr": "06:e6:97:9e:23:f5",
            "guest_2g_enable": "on",
            "wireless_2g_enable": "on"
        }
    }
    '''
        perf_stats = '''
      {
          "data": {"mem_usage":0.47, "cpu_usage":0.25},
          "timeout": false,
          "success": true,
          "operator": "load"
      }
    '''
        response_stats = '''
      {
          "data": [],
          "timeout": false,
          "success": true,
          "operator": "load"
      }
    '''

        class TPLinkRouterTest(TplinkRouter):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/status?form=all&operation=read':
                    return loads(response_status)['data']
                elif path == 'admin/status?form=perf&operation=read':
                    return loads(perf_stats)['data']
                elif path == 'admin/wireless?form=statistics':
                    return loads(response_stats)['data']
                raise ClientException()

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, None)
        self.assertEqual(status.lan_macaddr, '06-E6-97-9E-23-F5')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, None)
        self.assertEqual(status.lan_ipv4_addr, None)
        self.assertEqual(status.wan_ipv4_gateway, None)
        self.assertEqual(status.wired_total, 0)
        self.assertEqual(status.wifi_clients_total, 0)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 0)
        self.assertEqual(status.iot_clients_total, None)
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
        self.assertEqual(status.mem_usage, 0.47)
        self.assertEqual(status.cpu_usage, 0.25)
        self.assertEqual(len(status.devices), 0)

    def test_set_wifi(self) -> None:
        check_url = ''
        check_data = ''

        class TPLinkRouterTest(TplinkRouter):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                nonlocal check_url, check_data
                check_url = path
                check_data = data
                return None

        client = TPLinkRouterTest('', '')
        result = client.set_wifi(Connection.HOST_2G, False)
        self.assertIsNone(result)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=wireless_2g')
        self.assertEqual(check_data, 'operation=write&wireless_2g_enable=off')
        client.set_wifi(Connection.HOST_2G, True)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=wireless_2g')
        self.assertEqual(check_data, 'operation=write&wireless_2g_enable=on')
        client.set_wifi(Connection.HOST_5G, False)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=wireless_5g')
        self.assertEqual(check_data, 'operation=write&wireless_5g_enable=off')
        client.set_wifi(Connection.HOST_6G, True)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=wireless_6g')
        self.assertEqual(check_data, 'operation=write&wireless_6g_enable=on')
        client.set_wifi(Connection.GUEST_2G, True)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=guest_2g')
        self.assertEqual(check_data, 'operation=write&guest_2g_enable=on')
        client.set_wifi(Connection.GUEST_5G, False)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=guest_5g')
        self.assertEqual(check_data, 'operation=write&guest_5g_enable=off')
        client.set_wifi(Connection.GUEST_6G, True)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=guest_6g')
        self.assertEqual(check_data, 'operation=write&guest_6g_enable=on')
        client.set_wifi(Connection.IOT_2G, True)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=iot_2g')
        self.assertEqual(check_data, 'operation=write&iot_2g_enable=on')
        client.set_wifi(Connection.IOT_5G, False)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=iot_5g')
        self.assertEqual(check_data, 'operation=write&iot_5g_enable=off')
        client.set_wifi(Connection.IOT_6G, True)
        self.assertEqual(check_url, 'admin/wireless?&form=guest&form=iot_6g')
        self.assertEqual(check_data, 'operation=write&iot_6g_enable=on')


if __name__ == '__main__':
    main()
