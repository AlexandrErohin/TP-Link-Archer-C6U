from unittest import main, TestCase
from json import loads
from macaddress import EUI48
from ipaddress import IPv4Address
from tplinkrouterc6u import (
    TPLinkDecoClient,
    Connection,
    Firmware,
    Status,
    Device,
    IPv4Status,
)


class TestTPLinkDecoClient(TestCase):

    def test_get_status(self) -> None:
        response_network = '''
{"result": {
    "wan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:36",
            "dns2": "0.0.0.0",
            "dns1": "192.168.1.1",
            "mask": "255.255.255.0",
            "gateway": "192.168.1.1",
            "ip": "192.168.1.11"
            },
        "dial_type": "dynamic_ip", "info": {}, "enable_auto_dns": true},
    "lan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:37",
            "mask": "255.255.255.0",
            "ip": "192.168.68.1"
    }}}, "error_code": 0}
'''
        response_performance = '{"result": {"mem_usage": 0.43, "cpu_usage": 0.1}, "error_code": 0}'
        response_wireless = '''
{"result": {
    "band5_1": {"backhaul": {"channel": 44},
        "guest": {"password": "dGVzdDExMQ==", "ssid": "dGVzdF9HdWVzdA==", "vlan_id": 591,
                    "enable": false, "need_set_vlan": false},
        "host": {"password": "dGVzdDExMQ==", "ssid": "dGVzdA==", "channel": 44,
        "enable": true, "mode": "11ac", "channel_width": "HT80", "enable_hide_ssid": false}}, "is_eg": false,
    "band2_4": {"backhaul": {"channel": 10},
        "guest": {"password": "dGVzdDExMQ==", "ssid": "dGVzdF9HdWVzdA==", "vlan_id": 591,
                    "enable": true, "need_set_vlan": false},
        "host": {"password": "dGVzdDExMQ==", "ssid": "dGVzdA==", "channel": 10, "enable": true, "mode": "11ng",
                    "channel_width": "HT40", "enable_hide_ssid": false}}}, "error_code": 0}
'''
        response_clients = '''
{"result": {"client_list": [
        {"mac": "cf:51:c9:04:e1:02", "up_speed": 17, "down_speed": 3, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band5", "space_id": "1", "ip": "192.168.68.101", "client_mesh": true,
                "online": true, "name": "d2lyZWxlc3Mx", "enable_priority": false, "remain_time": 0,
                "owner_id": "", "client_type": "other", "interface": "main"},
        {"mac": "5f:f8:08:28:af:54", "up_speed": 3, "down_speed": 1, "wire_type": "wired", "access_host": "1",
                "connection_type": "wired", "space_id": "1", "ip": "192.168.68.100", "online": true, "name": "d2lyZWQx",
                "enable_priority": false, "remain_time": 0, "owner_id": "", "client_type": "other",
                "interface": "main"},
        {"mac": "92:28:a8:b7:d5:e6", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band5", "space_id": "1", "ip": "192.168.68.102", "client_mesh": true,
                "online": false, "name": "d2lyZWxlc3My", "enable_priority": false, "remain_time": 0, "owner_id": "",
                "client_type": "other", "interface": "main"},
        {"mac": "6b:35:fe:21:a7:73", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band2_4", "space_id": "1", "ip": "192.168.68.103", "online": true,
                "name": "d2lyZWxlc3Mz", "enable_priority": false, "remain_time": 0, "owner_id": "",
                "client_type": "other", "interface": "main"},
        {"mac": "19:90:f7:61:66:b2", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band5", "space_id": "1", "ip": "192.168.68.104", "client_mesh": true,
                "online": true, "name": "d2lyZWxlc3M0", "enable_priority": false, "remain_time": 0, "owner_id": "",
                "client_type": "other", "interface": "guest"},
        {"mac": "", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band2_4", "space_id": "1", "ip": "UNKNOWN", "client_mesh": true,
                "online": true, "name": "d2lyZWxlc3M1", "enable_priority": false, "remain_time": 0, "owner_id": "",
                "client_type": "other", "interface": "guest"}
]}, "error_code": 0}
'''

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/network?form=wan_ipv4':
                    return loads(response_network)['result']
                elif path == 'admin/network?form=performance':
                    return loads(response_performance)['result']
                elif path == 'admin/wireless?form=wlan':
                    return loads(response_wireless)['result']
                elif path == 'admin/client?form=client_list':
                    return loads(response_clients)['result']

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, '44-E1-52-8C-40-36')
        self.assertEqual(status.lan_macaddr, '44-E1-52-8C-40-37')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '192.168.1.11')
        self.assertEqual(status.lan_ipv4_addr, '192.168.68.1')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.1.1')
        self.assertEqual(status.wired_total, 1)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 2)
        self.assertEqual(status.iot_clients_total, None)
        self.assertEqual(status.clients_total, 5)
        self.assertEqual(status.guest_2g_enable, True)
        self.assertEqual(status.guest_5g_enable, False)
        self.assertEqual(status.guest_6g_enable, None)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.iot_6g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, True)
        self.assertEqual(status.wifi_6g_enable, None)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertEqual(status.mem_usage, 0.43)
        self.assertEqual(status.cpu_usage, 0.1)
        self.assertEqual(len(status.devices), 5)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.HOST_5G)
        self.assertEqual(status.devices[0].macaddr, 'CF-51-C9-04-E1-02')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.68.101')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'wireless1')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.WIRED)
        self.assertEqual(status.devices[1].macaddr, '5F-F8-08-28-AF-54')
        self.assertEqual(status.devices[1].ipaddr, '192.168.68.100')
        self.assertEqual(status.devices[1].hostname, 'wired1')
        self.assertEqual(status.devices[1].packets_sent, None)
        self.assertEqual(status.devices[1].packets_received, None)
        self.assertIsInstance(status.devices[2], Device)
        self.assertEqual(status.devices[2].type, Connection.HOST_2G)
        self.assertEqual(status.devices[2].macaddr, '6B-35-FE-21-A7-73')
        self.assertEqual(status.devices[2].ipaddr, '192.168.68.103')
        self.assertEqual(status.devices[2].hostname, 'wireless3')
        self.assertEqual(status.devices[2].packets_sent, None)
        self.assertEqual(status.devices[2].packets_received, None)
        self.assertIsInstance(status.devices[3], Device)
        self.assertEqual(status.devices[3].type, Connection.GUEST_5G)
        self.assertEqual(status.devices[3].macaddr, '19-90-F7-61-66-B2')
        self.assertEqual(status.devices[3].ipaddr, '192.168.68.104')
        self.assertEqual(status.devices[3].hostname, 'wireless4')
        self.assertEqual(status.devices[3].packets_sent, None)
        self.assertEqual(status.devices[3].packets_received, None)
        self.assertIsInstance(status.devices[4], Device)
        self.assertEqual(status.devices[4].type, Connection.GUEST_2G)
        self.assertEqual(status.devices[4].macaddr, '00-00-00-00-00-00')
        self.assertEqual(status.devices[4].ipaddr, '0.0.0.0')
        self.assertEqual(status.devices[4].hostname, 'wireless5')
        self.assertEqual(status.devices[4].packets_sent, None)
        self.assertEqual(status.devices[4].packets_received, None)

    def test_get_status_iot(self) -> None:
        response_network = '''
{"result": {
    "wan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:36", "dns2": "0.0.0.0", "dns1": "0.0.0.0", "mask": "", "gateway": "", "ip": ""
            },
        "dial_type": "dynamic_ip", "info": {}, "enable_auto_dns": true},
    "lan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:37",
            "mask": "255.255.255.0",
            "ip": "192.168.68.1"
    }}}, "error_code": 0}
'''
        response_performance = '{"result": {"mem_usage": 0.43, "cpu_usage": 0.1}, "error_code": 0}'
        response_wireless = '''
{"result": {
    "band5_1": {"backhaul": {"channel": 44},
        "guest": {"password": "dGVzdDExMQ==", "ssid": "dGVzdF9HdWVzdA==", "vlan_id": 591,
                    "enable": false, "need_set_vlan": false},
        "host": {"password": "dGVzdDExMQ==", "ssid": "dGVzdA==", "channel": 44,
        "enable": false, "mode": "11ac", "channel_width": "HT80", "enable_hide_ssid": false}}, "is_eg": false,
    "band6": {"backhaul": {"channel": 37},
        "guest": {"password": "dGVzdDExMQ==", "ssid": "dGVzdF9HdWVzdA==", "vlan_id": 591,
                    "enable": false, "need_set_vlan": false},
        "host": {"password": "dGVzdDExMQ==", "ssid": "dGVzdA==", "channel": 44,
        "enable": true, "mode": "11ac", "channel_width": "HT80", "enable_hide_ssid": false}}, "is_eg": false,
    "band2_4": {"backhaul": {"channel": 10},
        "guest": {"password": "dGVzdDExMQ==", "ssid": "dGVzdF9HdWVzdA==", "vlan_id": 591,
                    "enable": true, "need_set_vlan": false},
        "host": {"password": "dGVzdDExMQ==", "ssid": "dGVzdA==", "channel": 10, "enable": true, "mode": "11ng",
                    "channel_width": "HT40", "enable_hide_ssid": false}}}, "error_code": 0}
'''
        response_clients = '''{"result": {"client_list": [
        {"mac": "cf:51:c9:04:e1:02", "up_speed": 17, "down_speed": 3, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band5", "space_id": "1", "ip": "", "client_mesh": true,
                "online": true, "name": "d2lyZWxlc3Mx", "enable_priority": false, "remain_time": 0,
                "owner_id": "", "client_type": "other", "interface": "main"},
        {"mac": "5f:f8:08:28:af:54", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band2_4", "space_id": "1", "ip": "192.168.68.100", "online": true,
                "name": "d2lyZWQx", "enable_priority": false, "remain_time": 0, "owner_id": "",
                "client_type": "iot_device", "interface": "iot"},
        {"mac": "5f:f8:08:28:af:55", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band5", "space_id": "1", "ip": "192.168.68.101", "online": true,
                "name": "d2lyZWQx", "enable_priority": false, "remain_time": 0, "owner_id": "",
                "client_type": "iot_device", "interface": "iot"},
        {"mac": "5f:f8:08:28:af:56", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "connection_type": "band6", "space_id": "1", "ip": "192.168.68.102", "online": true,
                "name": "d2lyZWQx", "enable_priority": false, "remain_time": 0, "owner_id": "",
                "client_type": "iot_device", "interface": "iot"},
        {"mac": "5f:f8:08:28:af:57", "up_speed": 3, "down_speed": 1, "wire_type": "wireless", "access_host": "1",
                "space_id": "1", "ip": "192.168.68.103", "online": true, "name": "d2lyZWQx",
                "enable_priority": false, "remain_time": 0, "owner_id": "", "client_type": "iot_device"}
]}, "error_code": 0}
'''

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/network?form=wan_ipv4':
                    return loads(response_network)['result']
                elif path == 'admin/network?form=performance':
                    return loads(response_performance)['result']
                elif path == 'admin/wireless?form=wlan':
                    return loads(response_wireless)['result']
                elif path == 'admin/client?form=client_list':
                    return loads(response_clients)['result']

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertEqual(status.wired_total, 0)
        self.assertEqual(status.wifi_clients_total, 1)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.iot_clients_total, 3)
        self.assertEqual(status.clients_total, 4)
        self.assertEqual(status.guest_2g_enable, True)
        self.assertEqual(status.guest_5g_enable, False)
        self.assertEqual(status.guest_6g_enable, False)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.iot_6g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, False)
        self.assertEqual(status.wifi_6g_enable, True)

        self.assertEqual(len(status.devices), 5)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.HOST_5G)
        self.assertEqual(status.devices[0].macaddr, 'CF-51-C9-04-E1-02')
        self.assertEqual(status.devices[0].down_speed, 3)
        self.assertEqual(status.devices[0].up_speed, 17)
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.IOT_2G)
        self.assertEqual(status.devices[1].macaddr, '5F-F8-08-28-AF-54')
        self.assertIsInstance(status.devices[2], Device)
        self.assertEqual(status.devices[2].type, Connection.IOT_5G)
        self.assertEqual(status.devices[2].macaddr, '5F-F8-08-28-AF-55')
        self.assertIsInstance(status.devices[3], Device)
        self.assertEqual(status.devices[3].type, Connection.IOT_6G)
        self.assertEqual(status.devices[3].macaddr, '5F-F8-08-28-AF-56')
        self.assertIsInstance(status.devices[4], Device)
        self.assertEqual(status.devices[4].type, Connection.UNKNOWN)
        self.assertEqual(status.devices[4].macaddr, '5F-F8-08-28-AF-57')

    def test_get_status_no_internet(self) -> None:
        response_network = '''
{"result": {
    "wan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:36", "dns2": "0.0.0.0", "dns1": "0.0.0.0", "mask": "", "gateway": "", "ip": ""
            },
        "dial_type": "dynamic_ip", "info": {}, "enable_auto_dns": true},
    "lan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:37",
            "mask": "255.255.255.0",
            "ip": "192.168.68.1"
    }}}, "error_code": 0}
'''
        response_performance = '{"result": {"mem_usage": 0.43, "cpu_usage": 0.1}, "error_code": 0}'
        response_wireless = '''
{"result": {
    "band5_1": {"backhaul": {"channel": 44},
        "guest": {"password": "dGVzdDExMQ==", "ssid": "dGVzdF9HdWVzdA==", "vlan_id": 591,
                    "enable": false, "need_set_vlan": false},
        "host": {"password": "dGVzdDExMQ==", "ssid": "dGVzdA==", "channel": 44,
        "enable": true, "mode": "11ac", "channel_width": "HT80", "enable_hide_ssid": false}}, "is_eg": false,
    "band2_4": {"backhaul": {"channel": 10},
        "guest": {"password": "dGVzdDExMQ==", "ssid": "dGVzdF9HdWVzdA==", "vlan_id": 591,
                    "enable": true, "need_set_vlan": false},
        "host": {"password": "dGVzdDExMQ==", "ssid": "dGVzdA==", "channel": 10, "enable": true, "mode": "11ng",
                    "channel_width": "HT40", "enable_hide_ssid": false}}}, "error_code": 0}
'''
        response_clients = '{"result": {"client_list": []}, "error_code": 0}'

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/network?form=wan_ipv4':
                    return loads(response_network)['result']
                elif path == 'admin/network?form=performance':
                    return loads(response_performance)['result']
                elif path == 'admin/wireless?form=wlan':
                    return loads(response_wireless)['result']
                elif path == 'admin/client?form=client_list':
                    return loads(response_clients)['result']

        client = TPLinkRouterTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, '44-E1-52-8C-40-36')
        self.assertEqual(status.lan_macaddr, '44-E1-52-8C-40-37')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, None)
        self.assertEqual(status.lan_ipv4_addr, '192.168.68.1')
        self.assertEqual(status.wan_ipv4_gateway, None)
        self.assertEqual(status.wired_total, 0)
        self.assertEqual(status.wifi_clients_total, 0)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 0)
        self.assertEqual(len(status.devices), 0)

    def test_get_ipv4_status(self) -> None:
        response_network = '''
        {"result": {
            "wan": {
                "ip_info": {
                    "mac": "44:e1:52:8c:40:36",
                    "dns2": "0.0.0.0",
                    "dns1": "192.168.1.1",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.1.1",
                    "ip": "192.168.1.11"
                    },
                "dial_type": "dynamic_ip", "info": {}, "enable_auto_dns": true},
            "lan": {
                "ip_info": {
                    "mac": "44:e1:52:8c:40:37",
                    "mask": "255.255.255.0",
                    "ip": "192.168.68.1"
            }}}, "error_code": 0}
        '''

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/network?form=wan_ipv4':
                    return loads(response_network)['result']

        client = TPLinkRouterTest('', '')
        result = client.get_ipv4_status()

        self.assertIsInstance(result, IPv4Status)
        self.assertEqual(result.wan_macaddr, '44-E1-52-8C-40-36')
        self.assertEqual(result.wan_ipv4_ipaddr, '192.168.1.11')
        self.assertEqual(result.wan_ipv4_gateway, '192.168.1.1')
        self.assertEqual(result.wan_ipv4_conntype, 'dynamic_ip')
        self.assertEqual(result.wan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(result.wan_ipv4_pridns, '192.168.1.1')
        self.assertEqual(result.wan_ipv4_snddns, '0.0.0.0')
        self.assertEqual(result.lan_macaddr, '44-E1-52-8C-40-37')
        self.assertEqual(result.lan_ipv4_ipaddr, '192.168.68.1')
        self.assertEqual(result.lan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(result.lan_ipv4_dhcp_enable, False)
        self.assertEqual(result.remote, None)

    def test_get_ipv4_status_no_internet(self) -> None:
        response_network = '''
{"result": {
    "wan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:36", "dns2": "0.0.0.0", "dns1": "0.0.0.0", "mask": "", "gateway": "", "ip": ""
            },
        "dial_type": "dynamic_ip", "info": {}, "enable_auto_dns": true},
    "lan": {
        "ip_info": {
            "mac": "44:e1:52:8c:40:37",
            "mask": "255.255.255.0",
            "ip": "192.168.68.1"
    }}}, "error_code": 0}
'''

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/network?form=wan_ipv4':
                    return loads(response_network)['result']

        client = TPLinkRouterTest('', '')
        result = client.get_ipv4_status()

        self.assertIsInstance(result, IPv4Status)
        self.assertEqual(result.wan_macaddr, '44-E1-52-8C-40-36')
        self.assertEqual(result.wan_ipv4_ipaddr, None)
        self.assertEqual(result.wan_ipv4_gateway, None)
        self.assertEqual(result.wan_ipv4_conntype, 'dynamic_ip')
        self.assertEqual(result.wan_ipv4_netmask, None)
        self.assertEqual(result.wan_ipv4_pridns, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_snddns, '0.0.0.0')
        self.assertEqual(result.lan_macaddr, '44-E1-52-8C-40-37')
        self.assertEqual(result.lan_ipv4_ipaddr, '192.168.68.1')
        self.assertEqual(result.lan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(result.lan_ipv4_dhcp_enable, False)
        self.assertEqual(result.remote, None)

    def test_get_firmware(self) -> None:
        response_firmware = '''
{"result": {"device_list": [
        {"nand_flash": false, "hardware_ver": "2.0", "bssid_sta_2g": "",
        "software_ver": "1.6.1 Build 20231227 Rel. 80438", "role": "master", "bssid_sta_5g": "",
        "inet_status": "online", "nickname": "bedroom", "oversized_firmware": false, "bssid_5g": "6b:3a:9b:93:f4:15",
        "set_gateway_support": true, "inet_error_msg": "well", "group_status": "connected", "mac": "84:a0:d0:37:c7:44",
        "bssid_2g": "5c:c6:06:e7:87:d9", "support_plc": false, "oem_id": "fdfgdfgdgdfgdfg",
        "signal_level": {"band5": "0", "band2_4": "0"}, "product_level": 100, "device_ip": "192.168.68.1",
        "device_model": "M4R", "hw_id": "fgtrhxg43rgsdgbfdgbf", "device_type": "HOMEWIFISYSTEM"}]},
"error_code": 0}
    '''
        response_firmware = loads(response_firmware)

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/device?form=device_list':
                    return response_firmware['result']

        client = TPLinkRouterTest('', '')
        result = client.get_firmware()

        self.assertIsInstance(result, Firmware)
        self.assertEqual(result.hardware_version, '2.0')
        self.assertEqual(result.model, 'M4R')
        self.assertEqual(result.firmware_version, '1.6.1 Build 20231227 Rel. 80438')
        self.assertEqual(response_firmware['result']['device_list'], client.devices)

    def test_get_firmware_two_devices(self) -> None:
        response_firmware = '''
{"result": {"device_list": [{"nand_flash": false, "owner_transfer": true, "previous": "2d:a9:80:57:f9:05",
        "device_ip": "192.168.68.250", "bssid_2g": "ab:e4:7e:33:04:a6", "parent_device_id": "gdfgdfgdfgdfg",
        "software_ver": "1.5.49", "role": "slave", "bssid_sta_5g": "91:4d:4e:b4:8a:fd",
        "hardware_ver": "5", "device_id": "ssdfsfsdfsdfsdf", "product_level": 100, "inet_status": "online",
        "nickname": "kitchen", "bssid_5g": "8e:79:41:b5:66:df", "connection_type": ["band2_4", "band5"],
        "set_gateway_support": true, "inet_error_msg": "well", "group_status": "connected", "mac": "2b:19:b1:0a:90:d4",
        "bssid_sta_2g": "be:e1:db:01:4b:ab", "support_plc": false, "oem_id": "fdhfdghfhggfh",
        "signal_level": {"band2_4": "3", "band5": "2"}, "device_model": "model", "oversized_firmware": false,
        "speed_get_support": true, "hw_id": "ergsdfgsrgdfg", "device_type": "HOMEWIFISYSTEM"},
        {"nand_flash": false, "hardware_ver": "2.0", "bssid_sta_2g": "", "software_ver": "1.6.1 Build 20231227",
        "role": "master", "bssid_sta_5g": "", "previous": "", "inet_status": "online", "nickname": "bedroom",
        "oversized_firmware": false, "bssid_5g": "1e:ec:fd:7f:a0:e0", "set_gateway_support": true,
        "inet_error_msg": "well", "group_status": "connected", "mac": "3b:50:c9:c5:c1:a2",
        "bssid_2g": "d7:bb:67:b0:f6:a7", "support_plc": false, "oem_id": "hfghfhfhfhgfhfgh",
        "signal_level": {"band5": "0", "band2_4": "0"}, "product_level": 100, "device_ip": "192.168.68.1",
        "device_model": "M4R", "hw_id": "jhfjhtyjghjfghj", "device_type": "HOMEWIFISYSTEM"}]}, "error_code": 0}
        '''
        response_firmware = loads(response_firmware)

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/device?form=device_list':
                    return response_firmware['result']

        client = TPLinkRouterTest('', '')
        result = client.get_firmware()

        self.assertIsInstance(result, Firmware)
        self.assertEqual(result.hardware_version, '2.0')
        self.assertEqual(result.model, 'M4R')
        self.assertEqual(result.firmware_version, '1.6.1 Build 20231227')
        self.assertEqual(response_firmware['result']['device_list'], client.devices)

    def test_set_wifi(self) -> None:
        check_url = ''
        check_data = ''

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                nonlocal check_url, check_data
                check_url = path
                check_data = data

        client = TPLinkRouterTest('', '')
        result = client.set_wifi(Connection.HOST_2G, False)
        self.assertIsNone(result)
        self.assertEqual(check_url, 'admin/wireless?form=wlan')
        self.assertEqual(check_data, '{"operation": "write", "params": {"band2_4": {"host": {"enable": false}}}}')
        client.set_wifi(Connection.HOST_2G, True)
        self.assertEqual(check_data, '{"operation": "write", "params": {"band2_4": {"host": {"enable": true}}}}')
        client.set_wifi(Connection.HOST_5G, True)
        self.assertEqual(check_data, '{"operation": "write", "params": {"band5_1": {"host": {"enable": true}}}}')
        client.set_wifi(Connection.GUEST_2G, True)
        self.assertEqual(check_data, '{"operation": "write", "params": {"band2_4": {"guest": {"enable": true}}}}')
        client.set_wifi(Connection.GUEST_5G, True)
        self.assertEqual(check_data, '{"operation": "write", "params": {"band5_1": {"guest": {"enable": true}}}}')
        client.set_wifi(Connection.HOST_6G, True)
        self.assertEqual(check_data, '{"operation": "write", "params": {"band6": {"host": {"enable": true}}}}')
        client.set_wifi(Connection.GUEST_6G, True)
        self.assertEqual(check_data, '{"operation": "write", "params": {"band6": {"guest": {"enable": true}}}}')

    def test_reboot_with_firmware(self) -> None:
        check_url = ''
        check_data = ''

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                nonlocal check_url, check_data
                check_url = path
                check_data = data

        client = TPLinkRouterTest('', '')
        client.devices = [{'mac': 'mac1'}, {'mac': 'mac2'}, ]
        result = client.reboot()
        self.assertIsNone(result)
        self.assertEqual(check_url, 'admin/device?form=system')
        self.assertEqual(check_data,
                         '{"operation": "reboot", "params": {"mac_list": [{"mac": "mac1"}, {"mac": "mac2"}]}}')

    def test_reboot_no_firmware(self) -> None:
        response_firmware = '''
        {"result": {"device_list": [
                {"nand_flash": false, "hardware_ver": "2.0", "bssid_sta_2g": "",
                "software_ver": "1.6.1 Build 20231227 Rel. 80438", "role": "master", "bssid_sta_5g": "",
                "inet_status": "online", "nickname": "bedroom", "oversized_firmware": false,
                "bssid_5g": "6b:3a:9b:93:f4:15", "set_gateway_support": true, "inet_error_msg": "well",
                "group_status": "connected", "mac": "84:a0:d0:37:c7:44",  "bssid_2g": "5c:c6:06:e7:87:d9",
                "support_plc": false, "oem_id": "fdfgdfgdgdfgdfg",
                "signal_level": {"band5": "0", "band2_4": "0"}, "product_level": 100, "device_ip": "192.168.68.1",
                "device_model": "M4R", "hw_id": "fgtrhxg43rgsdgbfdgbf", "device_type": "HOMEWIFISYSTEM"}]},
        "error_code": 0}
            '''
        response_firmware = loads(response_firmware)
        check_url = ''
        check_data = ''

        class TPLinkRouterTest(TPLinkDecoClient):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/device?form=device_list':
                    return response_firmware['result']
                nonlocal check_url, check_data
                check_url = path
                check_data = data

        client = TPLinkRouterTest('', '')
        result = client.reboot()
        self.assertIsNone(result)
        self.assertEqual(check_url, 'admin/device?form=system')
        self.assertEqual(check_data, '{"operation": "reboot", "params": {"mac_list": [{"mac": "84:a0:d0:37:c7:44"}]}}')
        self.assertEqual(response_firmware['result']['device_list'], client.devices)


if __name__ == '__main__':
    main()
