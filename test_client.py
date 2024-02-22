import unittest
from tplinkrouterc6u import TPLinkMRClient, Wifi


class TestTPLinkMRClient(unittest.TestCase):
    def test_merge_response(self):
        response = '''[1,1,0,0,0,0]0
X_TP_MACAddress=mac1
IPInterfaceIPAddress=192.168.4.1
[1,1,1,0,0,0]1
enable=1
MACAddress=mac2
externalIPAddress=192.168.30.55
defaultGateway=192.168.30.1
name=ipoe_1_d
subnetMask=255.255.255.0
DNSServers=192.168.3.1,0.0.0.0
[2,1,1,0,0,0]1
enable=0
MACAddress=
externalIPAddress=0.0.0.0
defaultGateway=0.0.0.0
name=LTE
subnetMask=0.0.0.0
DNSServers=0.0.0.0,0.0.0.0
[1,1,0,0,0,0]2
enable=1
X_TP_Band=2.4GHz
[1,2,0,0,0,0]2
enable=1
X_TP_Band=5GHz
[1,1,0,0,0,0]3
enable=0
name=wlan1
[1,2,0,0,0,0]3
enable=1
name=wlan6
[error]0'''
        client = TPLinkMRClient('', '')
        result = client._merge_response(response)
        self.assertEqual(len(result), 4)
        self.assertEqual(len(result[1]), 2)
        self.assertEqual(len(result[2]), 2)
        self.assertEqual(len(result[3]), 2)
        self.assertEqual(result[0]['X_TP_MACAddress'], 'mac1')
        self.assertEqual(result[1][0]['name'], 'ipoe_1_d')
        self.assertEqual(result[1][1]['name'], 'LTE')
        self.assertEqual(result[2][0]['X_TP_Band'], '2.4GHz')
        self.assertEqual(result[2][1]['X_TP_Band'], '5GHz')
        self.assertEqual(result[3][0]['name'], 'wlan1')
        self.assertEqual(result[3][1]['name'], 'wlan6')

    def test_get_status_with_5G(self):
        response = '''[1,1,0,0,0,0]0
X_TP_MACAddress=a0:28:84:de:dd:5c
IPInterfaceIPAddress=192.168.4.1
[2,1,1,0,0,0]1
enable=0
MACAddress=
externalIPAddress=0.0.0.0
defaultGateway=0.0.0.0
name=LTE
subnetMask=0.0.0.0
DNSServers=0.0.0.0,0.0.0.0
[1,1,1,0,0,0]1
enable=1
MACAddress=bf:75:44:4c:dc:9e
externalIPAddress=192.168.30.55
defaultGateway=192.168.30.1
name=ipoe_1_d
subnetMask=255.255.255.0
DNSServers=192.168.3.1,0.0.0.0
[1,1,0,0,0,0]2
enable=1
X_TP_Band=2.4GHz
[1,2,0,0,0,0]2
enable=0
X_TP_Band=5GHz
[1,1,0,0,0,0]3
enable=0
name=wlan1
[1,2,0,0,0,0]3
enable=1
name=wlan6
[1,0,0,0,0,0]4
IPAddress=192.168.30.10
MACAddress=66:e2:02:bd:b5:1b
hostName=host1
X_TP_ConnType=0
active=1
[2,0,0,0,0,0]4
IPAddress=192.168.30.11
MACAddress=f4:a3:86:2d:41:b5
hostName=host2
X_TP_ConnType=3
active=1
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        status = client.get_status()

        self.assertEqual(status.wan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(status.lan_macaddr, 'A0-28-84-DE-DD-5C')
        self.assertEqual(status.wan_ipv4_addr, '192.168.30.55')
        self.assertEqual(status.lan_ipv4_addr, '192.168.4.1')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.30.1')
        self.assertEqual(status.wired_total, 1)
        self.assertEqual(status.wifi_clients_total, 1)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 2)
        self.assertEqual(status.guest_2g_enable, False)
        self.assertEqual(status.guest_5g_enable, True)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, False)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertEqual(status.mem_usage, None)
        self.assertEqual(status.cpu_usage, None)
        self.assertEqual(len(status.devices), 1)
        self.assertEqual(status.devices[0].type, Wifi.WIFI_5G)
        self.assertEqual(status.devices[0].macaddr, 'F4-A3-86-2D-41-B5')
        self.assertEqual(status.devices[0].ipaddr, '192.168.30.11')
        self.assertEqual(status.devices[0].hostname, 'host2')

    def test_get_status_without_5G(self):
        response = '''[1,1,0,0,0,0]0
X_TP_MACAddress=a0:28:84:de:dd:5c
IPInterfaceIPAddress=192.168.4.1
[1,1,1,0,0,0]1
enable=0
MACAddress=bf:75:44:4c:dc:9e
externalIPAddress=192.168.30.55
defaultGateway=192.168.30.1
name=ipoe_1_d
subnetMask=255.255.255.0
DNSServers=192.168.3.1,0.0.0.0
[1,1,0,0,0,0]2
enable=1
X_TP_Band=2.4GHz
[1,1,0,0,0,0]3
enable=0
name=wlan1
[1,0,0,0,0,0]4
IPAddress=192.168.30.10
MACAddress=66:e2:02:bd:b5:1b
hostName=host1
X_TP_ConnType=0
active=1
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        status = client.get_status()

        self.assertEqual(status.wan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(status.lan_macaddr, 'A0-28-84-DE-DD-5C')
        self.assertEqual(status.wan_ipv4_addr, '192.168.30.55')
        self.assertEqual(status.lan_ipv4_addr, '192.168.4.1')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.30.1')
        self.assertEqual(status.wired_total, 1)
        self.assertEqual(status.wifi_clients_total, 0)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 1)
        self.assertEqual(status.guest_2g_enable, False)
        self.assertEqual(status.guest_5g_enable, None)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, None)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertEqual(status.mem_usage, None)
        self.assertEqual(status.cpu_usage, None)
        self.assertEqual(len(status.devices), 0)


if __name__ == '__main__':
    unittest.main()
