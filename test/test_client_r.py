import json
from ipaddress import IPv4Address
from unittest import TestCase, main

from macaddress import EUI48

from tplinkrouterc6u.client.r import TPLinkRClient
from tplinkrouterc6u.common.dataclass import (Device, Firmware, IPv4DHCPLease,
                                              IPv4Reservation, Status)
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


class TestTPLinkRClient(TestCase):

    def test_supports_false(self) -> None:
        class SessionTest:
            def get(self, host, timeout, verify):
                class ResponseTest:
                    def __init__(self):
                        self.text = 'text'

                return ResponseTest()

        client = TPLinkRClient('', '')
        client._session = SessionTest()

        self.assertEqual(client.supports(), False)

    def test_supports_true(self) -> None:
        response = '''
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta data-interface-type="SLP" />
    <!-- ... -->
    <title>Opening...</title>
</head>
<body class="login-body">
<noscript>
    <meta http-equiv="refresh" content="0; url=error.htm"/>
</noscript>
<script type="text/javascript">
//<![CDATA[
$(document).ready(function(e){
    var radio = 0;
    var is_sar = 0;
    var locale = "zh_CN";
    var force = false;
    var model = "TL-R470GP-AC";
    // 是否是出厂设置
    // Default: 恢复出厂设置后第一次登录
    // Modify: 不是恢复出厂设置后第一次登录
    var config_status = "Modify";
    var interface_model = 5;
    var single_wan = 1;
    var interface_count = 5;
    var router_list = [{"mac":"80-EA-07-CC-28-B4","ip":"192.168.60.1","dev_name":"TL-R470GP-AC 4.0"}];
    // ...
});
//]]>
</script>
</body>
</html>
'''

        class SessionTest:
            def get(self, host, timeout, verify):
                class ResponseTest:
                    def __init__(self):
                        self.text = response

                return ResponseTest()

        client = TPLinkRClient('', '')
        client._session = SessionTest()

        self.assertEqual(client.supports(), True)

    def test_logout(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
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
      ".name": "info",
      "radio_count": "0",
      "zone_code": "0x0",
      "manufacturer_name": "TP-LINK",
      "sw_version": "2.0.0%20Build%20211008%20Rel.48276n",
      "manufacturer_url": "www.tp-link.com.cn",
      "language": "CN",
      "domain_name": "tplogin.cn",
      ".type": "info",
      "sys_software_revision": "0x500a0200",
      "product_id": "62042BE0",
      "fw_description": "R470GPACV4",
      "hw_version": "4.0",
      ".anonymous": false,
      "device_name": "TL-R470GP-AC%204.0",
      "vendor_id": "0x00000001",
      "device_model": "TL-R470GP-AC",
      "enable_dns": "1",
      "device_info": "TL-R470GP-AC%204.0",
      "sys_software_revision_minor": "0x0000",
      "device_type": "SMBROUTER"
    }
  },
  "error_code": 0
}
''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
        firmware = client.get_firmware()

        self.assertEqual(check_payload['method'], 'get')
        self.assertIn('device_info', check_payload)
        self.assertIn('name', check_payload['device_info'])
        self.assertEqual(check_payload['device_info']['name'], 'info')

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.firmware_version, '2.0.0 Build 211008 Rel.48276n')
        self.assertEqual(firmware.hardware_version, '4.0')
        self.assertEqual(firmware.model, 'TL-R470GP-AC')

    def test_get_status(self) -> None:
        mock_data = json.loads('''
{
  "apmng_wserv": {
    "wlan_serv": [
      {
        "wlan_serv_2": {
          "ssidbrd": "1",
          "encryption": "1",
          "radius_ip": "0.0.0.0",
          "isolate": "0",
          "is_sys": "1",
          "key": "xxxxxxxx",
          "bw_ctrl_mode": "1",
          "network_type": "1",
          "default_bind_freq": "127",
          "serv_id": "2",
          "down_limit": "0",
          "radius_port": "0",
          "up_limit": "0",
          "ssid": "xxx-IoT",
          "priv_key": "3",
          "cipher": "2",
          "bw_ctrl_enable": "0",
          "key_update_intv": "86400",
          "auto_bind": "on",
          "enable": "on",
          "default_bind_vlan": "0",
          "desc": "",
          "radius_acct_port": "0",
          "radius_pwd": "",
          "ssid_code_type": "1",
          "ssid_id": "",
          "auth": "2"
        }
      },
      {
        "wlan_serv_3": {
          "ssidbrd": "1",
          "encryption": "0",
          "radius_ip": "0.0.0.0",
          "isolate": "0",
          "is_sys": "1",
          "key": "0",
          "bw_ctrl_mode": "1",
          "network_type": "2",
          "default_bind_freq": "127",
          "serv_id": "3",
          "down_limit": "0",
          "radius_port": "0",
          "up_limit": "0",
          "ssid": "xxx-Guest",
          "priv_key": "4",
          "cipher": "0",
          "bw_ctrl_enable": "0",
          "key_update_intv": "86400",
          "auto_bind": "on",
          "enable": "off",
          "default_bind_vlan": "4084",
          "desc": "",
          "radius_acct_port": "0",
          "radius_pwd": "",
          "ssid_code_type": "1",
          "ssid_id": "",
          "auth": "3"
        }
      },
      {
        "wlan_serv_4": {
          "ssidbrd": "1",
          "encryption": "1",
          "radius_ip": "0.0.0.0",
          "isolate": "0",
          "is_sys": "1",
          "key": "xxxxxxxx",
          "bw_ctrl_mode": "1",
          "network_type": "1",
          "default_bind_freq": "32512",
          "serv_id": "4",
          "down_limit": "0",
          "radius_port": "0",
          "up_limit": "0",
          "ssid": "xxx",
          "priv_key": "5",
          "cipher": "2",
          "bw_ctrl_enable": "0",
          "key_update_intv": "86400",
          "auto_bind": "on",
          "enable": "on",
          "default_bind_vlan": "0",
          "desc": "",
          "radius_acct_port": "0",
          "radius_pwd": "",
          "ssid_code_type": "1",
          "ssid_id": "",
          "auth": "2"
        }
      }
    ],
    "count": {
      "wlan_serv": 3
    }
  },
  "host_management": {
    "host_info": [
      {
        "host_info_1": {
          "up_speed": "0",
          "connect_date": "2026%2f01%2f13",
          "encode": "1",
          "rssi": "-77",
          "host_save": "off",
          "ip": "192.168.60.112",
          "is_cur_host": false,
          "hostname": "iPhone",
          "connect_time": "15%3a57%3a41",
          "interface": "br-lan",
          "up_limit": "0",
          "type": "wireless",
          "ssid": "xxx",
          "freq_name": "5GHz",
          "state": "online",
          "freq_unit": "2",
          "down_speed": "0",
          "down_limit": "0",
          "vlan_id": "0",
          "mac": "46-22-C0-A6-AC-35",
          "ap_name": "xxx-ap"
        }
      },
      {
        "host_info_2": {
          "up_speed": "0",
          "connect_date": "2026%2f01%2f09",
          "encode": "1",
          "rssi": "-68",
          "host_save": "off",
          "ip": "192.168.60.11",
          "is_cur_host": false,
          "hostname": "chuangmi_camera_ipc013",
          "connect_time": "04%3a01%3a15",
          "interface": "br-lan",
          "up_limit": "0",
          "type": "wireless",
          "ssid": "xxx-IoT",
          "freq_name": "2.4GHz",
          "state": "online",
          "freq_unit": "1",
          "down_speed": "0",
          "down_limit": "0",
          "vlan_id": "0",
          "mac": "44-23-7C-8F-C2-42",
          "ap_name": "xxx-ap"
        }
      },
      {
        "host_info_3": {
          "up_speed": "9",
          "connect_date": "2026%2f01%2f13",
          "encode": "1",
          "rssi": "-54",
          "host_save": "off",
          "ip": "192.168.60.102",
          "is_cur_host": true,
          "hostname": "Mac",
          "connect_time": "18%3a30%3a14",
          "interface": "br-lan",
          "up_limit": "0",
          "type": "wireless",
          "ssid": "syt",
          "freq_name": "5GHz",
          "state": "online",
          "freq_unit": "2",
          "down_speed": "3",
          "down_limit": "0",
          "vlan_id": "0",
          "mac": "C6-FD-4C-A8-D5-BA",
          "ap_name": "yyy-ap"
        }
      }
    ],
    "count": {
      "host_info": 3
    }
  },
  "network": {
    "lan": {
      "ifname": [
        "eth0.1",
        "eth0.4084"
      ],
      "ipaddr": "192.168.60.1",
      "netmask": "255.255.255.0",
      "type": "bridge",
      "proto": "static",
      "prefix_if": "WAN",
      "ip6ifaceid": "eui64",
      "fac_ipaddr": "192.168.1.1",
      "prefix": "2408%3a8340%3a111%3a1111%3a%3a",
      "ip6addr": "2408%3a8340%3a111%3a1111%3a1111%3a111%3a1111%3a1111",
      "fac_netmask": "255.255.255.0",
      "macaddr": "80-EA-07-CC-28-B4",
      "ipv6_enable": "on",
      "ip_mode": "manual"
    },
    "wan_status": {
      "down_speed": 1077,
      "up_speed": 60,
      "pri_dns": "221.12.1.227",
      "link_status": 1,
      "netmask": "255.255.255.255",
      "error_code": 0,
      "phy_status": 1,
      "proto": "pppoe",
      "gateway": "172.21.192.1",
      "up_time": 403611,
      "snd_dns": "221.12.33.227",
      "ipaddr": "172.21.199.238"
    }
  },
  "error_code": 0
}
''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
        status = client.get_status()

        self.assertEqual(check_payload['method'], 'get')
        self.assertEqual(check_payload['host_management']['table'], ['host_info'])
        self.assertIn('network', check_payload)
        self.assertIn('name', check_payload['network'])
        self.assertEqual(check_payload['network']['name'], ['wan_status', 'lan'])
        self.assertIn('apmng_wserv', check_payload)
        self.assertEqual(check_payload['apmng_wserv']['table'], ['wlan_serv'])

        self.assertIsInstance(status, Status)
        self.assertEqual(status.lan_ipv4_addr, '192.168.60.1')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_macaddr, '80-EA-07-CC-28-B4')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '172.21.199.238')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertEqual(len(status.devices), 3)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.HOST_5G)
        self.assertEqual(status.devices[0].macaddr, '46-22-C0-A6-AC-35')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.60.112')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'iPhone')
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.HOST_2G)
        self.assertEqual(status.devices[1].macaddr, '44-23-7C-8F-C2-42')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.60.11')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'chuangmi_camera_ipc013')

    def test_set_wifi_enable_guest_2g(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
        client._guest_2g_serv_id = '2'
        client._wifi_2g_serv_id = '3'
        client._wifi_5g_serv_id = '4'
        client.set_wifi(Connection.GUEST_2G, True)

        self.assertEqual(check_payload['method'], 'set')
        self.assertEqual(check_payload['apmng_wserv']['table'], 'wlan_serv')
        self.assertEqual(check_payload['apmng_wserv']['filter'], [{'serv_id': '2'}])
        self.assertEqual(check_payload['apmng_wserv']['para'], {'enable': 'on'})

    def test_set_wifi_enable_host_2g(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
        client._guest_2g_serv_id = '2'
        client._wifi_2g_serv_id = '3'
        client._wifi_5g_serv_id = '4'
        client.set_wifi(Connection.HOST_2G, True)

        self.assertEqual(check_payload['method'], 'set')
        self.assertEqual(check_payload['apmng_wserv']['table'], 'wlan_serv')
        self.assertEqual(check_payload['apmng_wserv']['filter'], [{'serv_id': '3'}])
        self.assertEqual(check_payload['apmng_wserv']['para'], {'enable': 'on'})

    def test_set_wifi_disable_host_5g(self) -> None:
        mock_data = json.loads('''{"error_code":0}''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
        client._guest_2g_serv_id = '2'
        client._wifi_2g_serv_id = '3'
        client._wifi_5g_serv_id = '4'
        client.set_wifi(Connection.HOST_5G, False)

        self.assertEqual(check_payload['method'], 'set')
        self.assertEqual(check_payload['apmng_wserv']['table'], 'wlan_serv')
        self.assertEqual(check_payload['apmng_wserv']['filter'], [{'serv_id': '4'}])
        self.assertEqual(check_payload['apmng_wserv']['para'], {'enable': 'off'})

    def test_get_ipv4_reservations(self):
        mock_data = json.loads('''
{
  "dhcpd": {
    "count": {
      "dhcp_static": 1
    },
    "dhcp_static": [
      {
        "dhcp_static_1": {
          "mac": "44-23-7C-8F-C2-42",
          "note": "chuangmi_camera_ipc013",
          "name": "44237C8FC242%2b192.168.60.11",
          "enable": "on",
          "ip": "192.168.60.11",
          "dhcp_static_id": "1"
        }
      }
    ]
  },
  "error_code": 0
}
''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
        reservations = client.get_ipv4_reservations()

        self.assertEqual(check_payload['method'], 'get')
        self.assertIsInstance(check_payload['dhcpd'], dict)
        self.assertEqual(check_payload['dhcpd']['table'], 'dhcp_static')

        self.assertEqual(len(reservations), 1)
        self.assertIsInstance(reservations[0], IPv4Reservation)
        self.assertEqual(reservations[0].macaddr, '44-23-7C-8F-C2-42')
        self.assertIsInstance(reservations[0].macaddress, EUI48)
        self.assertEqual(reservations[0].macaddress, get_mac('44-23-7C-8F-C2-42'))
        self.assertEqual(reservations[0].ipaddr, '192.168.60.11')
        self.assertIsInstance(reservations[0].ipaddress, IPv4Address)
        self.assertEqual(reservations[0].ipaddress, get_ip('192.168.60.11'))
        self.assertEqual(reservations[0].hostname, 'chuangmi_camera_ipc013')

    def test_get_ipv4_dhcp_leases(self):
        mock_data = json.loads('''
{
  "dhcpd": {
    "dhcp_clients": [
      {
        "dhcp_client_1": {
          "expires": "PERMANENT",
          "ipaddr": "192.168.60.11",
          "hostname": "chuangmi_camera_ipc013",
          "macaddr": "44-23-7C-8F-C2-42",
          "interface": "lan"
        }
      },
      {
        "dhcp_client_8": {
          "expires": "114146",
          "ipaddr": "192.168.60.106",
          "hostname": "---",
          "macaddr": "56-16-70-01-11-B9",
          "interface": "lan"
        }
      }
    ],
    "count": {
      "dhcp_clients": 2
    }
  },
  "error_code": 0
}
''')
        check_payload = {}

        class TPLinkRClientTest(TPLinkRClient):
            def _request(self, payload: dict) -> dict:
                nonlocal check_payload
                check_payload = payload
                return mock_data

        client = TPLinkRClientTest('', '')
        dhcp_leases = client.get_ipv4_dhcp_leases()

        self.assertEqual(check_payload['method'], 'get')
        self.assertIsInstance(check_payload['dhcpd'], dict)
        self.assertEqual(check_payload['dhcpd']['table'], 'dhcp_clients')

        self.assertEqual(len(dhcp_leases), 2)
        self.assertIsInstance(dhcp_leases[0], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[0].macaddr, '44-23-7C-8F-C2-42')
        self.assertIsInstance(dhcp_leases[0].macaddress, EUI48)
        self.assertEqual(dhcp_leases[0].macaddress, get_mac('44-23-7C-8F-C2-42'))
        self.assertEqual(dhcp_leases[0].ipaddr, '192.168.60.11')
        self.assertIsInstance(dhcp_leases[0].ipaddress, IPv4Address)
        self.assertEqual(dhcp_leases[0].ipaddress, get_ip('192.168.60.11'))
        self.assertEqual(dhcp_leases[0].hostname, 'chuangmi_camera_ipc013')
        self.assertEqual(dhcp_leases[0].lease_time, 'Permanent')
        self.assertIsInstance(dhcp_leases[1], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[1].macaddr, '56-16-70-01-11-B9')
        self.assertIsInstance(dhcp_leases[1].macaddress, EUI48)
        self.assertEqual(dhcp_leases[1].macaddress, get_mac('56-16-70-01-11-B9'))
        self.assertEqual(dhcp_leases[1].ipaddr, '192.168.60.106')
        self.assertIsInstance(dhcp_leases[1].ipaddress, IPv4Address)
        self.assertEqual(dhcp_leases[1].ipaddress, get_ip('192.168.60.106'))
        self.assertEqual(dhcp_leases[1].hostname, '---')
        self.assertEqual(dhcp_leases[1].lease_time, '1 day, 7:42:26')


if __name__ == '__main__':
    main()
