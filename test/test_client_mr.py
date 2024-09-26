from unittest import main, TestCase
from macaddress import EUI48
from ipaddress import IPv4Address
from tplinkrouterc6u import (
    TPLinkMRClient,
    Connection,
    Firmware,
    Status,
    Device,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
)


class TestTPLinkMRClient(TestCase):
    def test_merge_response(self) -> None:
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
[1,2,0,0,0,0]5
test=10
[error]0'''
        client = TPLinkMRClient('', '')
        result = client._merge_response(response)
        self.assertEqual(len(result), 5)
        self.assertEqual(len(result['1']), 2)
        self.assertEqual(len(result['2']), 2)
        self.assertEqual(len(result['3']), 2)
        self.assertEqual(result['0']['X_TP_MACAddress'], 'mac1')
        self.assertEqual(result['1'][0]['name'], 'ipoe_1_d')
        self.assertEqual(result['1'][1]['name'], 'LTE')
        self.assertEqual(result['2'][0]['X_TP_Band'], '2.4GHz')
        self.assertEqual(result['2'][1]['X_TP_Band'], '5GHz')
        self.assertEqual(result['3'][0]['name'], 'wlan1')
        self.assertEqual(result['3'][1]['name'], 'wlan6')
        self.assertEqual(len(result['5']), 1)
        self.assertEqual(result['5']['test'], '10')

    def test_merge_response_no_response(self) -> None:
        response = '''
name=wlan6
[error]0

'''
        client = TPLinkMRClient('', '')
        result = client._merge_response(response)

        self.assertEqual(result, [])

    def test_firmware(self) -> None:
        response = '''
[0,0,0,0,0,0]0
hardwareVersion=Archer MR200 v5.3
modelName=Archer MR200
softwareVersion=1.1
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_firmware()

        self.assertIsInstance(result, Firmware)
        self.assertEqual(result.hardware_version, 'Archer MR200 v5.3')
        self.assertEqual(result.hardware_version, 'Archer MR200 v5.3')
        self.assertEqual(result.model, 'Archer MR200')
        self.assertEqual(result.firmware_version, '1.1')

    def test_get_status_with_5G(self) -> None:
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
[1,1,1,0,0,0]5
associatedDeviceMACAddress=f4:a3:86:2d:41:b5
X_TP_TotalPacketsSent=176
X_TP_TotalPacketsReceived=467
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, 'A0-28-84-DE-DD-5C')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '192.168.30.55')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.4.1')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.30.1')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
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
        self.assertEqual(len(status.devices), 2)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.WIRED)
        self.assertEqual(status.devices[0].macaddr, '66-E2-02-BD-B5-1B')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.30.10')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'host1')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.HOST_5G)
        self.assertEqual(status.devices[1].macaddr, 'F4-A3-86-2D-41-B5')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.30.11')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'host2')
        self.assertEqual(status.devices[1].packets_sent, 176)
        self.assertEqual(status.devices[1].packets_received, 467)

    def test_get_status_without_5G(self) -> None:
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
        self.assertEqual(len(status.devices), 1)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.WIRED)
        self.assertEqual(status.devices[0].macaddr, '66-E2-02-BD-B5-1B')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.30.10')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'host1')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)

    def test_get_status_with_wlan_dev(self) -> None:
        response = '''
[1,1,0,0,0,0]0
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
[1,1,1,0,0,0]5
associatedDeviceMACAddress=f4:a3:86:2d:41:b8
X_TP_TotalPacketsSent=176
X_TP_TotalPacketsReceived=467
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
        self.assertEqual(status.wired_total, 0)
        self.assertEqual(status.wifi_clients_total, 1)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 1)
        self.assertEqual(status.guest_2g_enable, False)
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
        self.assertEqual(len(status.devices), 1)
        self.assertEqual(status.devices[0].type, Connection.HOST_2G)
        self.assertEqual(status.devices[0].macaddr, 'F4-A3-86-2D-41-B8')
        self.assertEqual(status.devices[0].ipaddr, '0.0.0.0')
        self.assertEqual(status.devices[0].hostname, '')
        self.assertEqual(status.devices[0].packets_sent, 176)
        self.assertEqual(status.devices[0].packets_received, 467)

    def test_get_status_mr6400(self) -> None:
        response = '''
[1,1,0,0,0,0]0
X_TP_MACAddress=30:DE:3B:15:D0:22
IPInterfaceIPAddress=192.168.1.1
[2,1,1,0,0,0]1
enable=0
MACAddress=
externalIPAddress=0.0.0.0
defaultGateway=0.0.0.0
[1,1,0,0,0,0]2
enable=0
X_TP_Band=2.4GHz
[1,1,0,0,0,0]3
enable=0
name=wlan1
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        status = client.get_status()

        self.assertEqual(status.wan_macaddr, None)
        self.assertEqual(status.lan_macaddr, '30-DE-3B-15-D0-22')
        self.assertEqual(status.wan_ipv4_addr, '0.0.0.0')
        self.assertEqual(status.lan_ipv4_addr, '192.168.1.1')
        self.assertEqual(status.wan_ipv4_gateway, '0.0.0.0')
        self.assertEqual(status.wired_total, 0)
        self.assertEqual(status.wifi_clients_total, 0)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 0)
        self.assertEqual(status.guest_2g_enable, False)
        self.assertEqual(status.guest_5g_enable, None)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.wifi_2g_enable, False)
        self.assertEqual(status.wifi_5g_enable, None)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertEqual(status.mem_usage, None)
        self.assertEqual(status.cpu_usage, None)
        self.assertEqual(len(status.devices), 0)

    def test_get_status_two_lan_ip(self) -> None:
        response = '''[1,1,0,0,0,0]0
X_TP_MACAddress=f5:e4:3b:e9:bf:c7
IPInterfaceIPAddress=192.168.1.1
[1,2,0,0,0,0]0
X_TP_MACAddress=4f5:e4:3b:e9:bf:c7
IPInterfaceIPAddress=192.168.0.110
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
[error]0
'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, 'F5-E4-3B-E9-BF-C7')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '192.168.30.55')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.1.1')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.30.1')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertEqual(status.wired_total, 0)
        self.assertEqual(status.wifi_clients_total, 0)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.iot_clients_total, None)
        self.assertEqual(status.clients_total, 0)
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

    def test_get_ipv4_reservations(self) -> None:
        response = '''
[1,1,0,0,0,0]0
enable=1
chaddr=bf:75:44:4c:dc:9e
yiaddr=192.168.8.21
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_ipv4_reservations()

        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], IPv4Reservation)
        self.assertEqual(result[0].macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result[0].ipaddr, '192.168.8.21')
        self.assertEqual(result[0].hostname, '')
        self.assertEqual(result[0].enabled, True)

    def test_get_ipv4_reservations_no_reservations(self) -> None:
        response = '''
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_ipv4_reservations()

        self.assertEqual(len(result), 0)

    def test_get_ipv4_dhcp_leases_no_leases(self) -> None:
        response = '''
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_ipv4_dhcp_leases()

        self.assertEqual(len(result), 0)

    def test_get_ipv4_dhcp_leases(self) -> None:
        response = '''
[1,0,0,0,0,0]0
IPAddress=192.168.32.175
MACAddress=bf:75:44:4c:dc:9e
hostName=name1
leaseTimeRemaining=85841
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_ipv4_dhcp_leases()

        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], IPv4DHCPLease)
        self.assertEqual(result[0].macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result[0].ipaddr, '192.168.32.175')
        self.assertEqual(result[0].hostname, 'name1')
        self.assertEqual(result[0].lease_time, '23:50:41')

    def test_get_ipv4_dhcp_leases_permanent(self) -> None:
        response = '''
[1,0,0,0,0,0]0
IPAddress=192.168.32.175
MACAddress=bf:75:44:4c:dc:9e
hostName=name1
leaseTimeRemaining=-1
[2,0,0,0,0,0]0
IPAddress=192.168.32.176
MACAddress=a0:28:84:de:dd:5c
hostName=name2
leaseTimeRemaining=86372
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_ipv4_dhcp_leases()

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result[0].ipaddr, '192.168.32.175')
        self.assertEqual(result[0].hostname, 'name1')
        self.assertEqual(result[0].lease_time, 'Permanent')
        self.assertEqual(result[1].macaddr, 'A0-28-84-DE-DD-5C')
        self.assertEqual(result[1].ipaddr, '192.168.32.176')
        self.assertEqual(result[1].hostname, 'name2')
        self.assertEqual(result[1].lease_time, '23:59:32')

    def test_get_ipv4_status(self) -> None:
        response = '''
[1,1,0,0,0,0]0
X_TP_MACAddress=bf:75:44:4c:dc:9e
IPInterfaceIPAddress=192.168.5.1
IPInterfaceSubnetMask=255.255.255.0
[1,0,0,0,0,0]1
DHCPServerEnable=1
[1,1,1,0,0,0]2
enable=0
MACAddress=
externalIPAddress=0.0.0.0
defaultGateway=0.0.0.0
name=ipoe_1_d
subnetMask=0.0.0.0
DNSServers=0.0.0.0,0.0.0.0
[2,1,1,0,0,0]2
enable=1
MACAddress=a0:28:84:de:dd:5c
externalIPAddress=10.10.11.5
defaultGateway=11.11.11.11
name=LTE
subnetMask=1.1.1.1
DNSServers=7.7.7.7,2.2.2.2
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_ipv4_status()

        self.assertIsInstance(result, IPv4Status)
        self.assertEqual(result.wan_macaddr, 'A0-28-84-DE-DD-5C')
        self.assertEqual(result.wan_ipv4_ipaddr, '10.10.11.5')
        self.assertEqual(result.wan_ipv4_gateway, '11.11.11.11')
        self.assertEqual(result.wan_ipv4_conntype, 'LTE')
        self.assertEqual(result.wan_ipv4_netmask, '1.1.1.1')
        self.assertEqual(result.wan_ipv4_pridns, '7.7.7.7')
        self.assertEqual(result.wan_ipv4_snddns, '2.2.2.2')
        self.assertEqual(result.lan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result.lan_ipv4_ipaddr, '192.168.5.1')
        self.assertEqual(result.lan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(result.lan_ipv4_dhcp_enable, True)
        self.assertEqual(result.remote, None)

    def test_get_ipv4_status_one_wlan(self) -> None:
        response = '''
[1,1,0,0,0,0]0
X_TP_MACAddress=bf:75:44:4c:dc:9e
IPInterfaceIPAddress=192.168.5.1
IPInterfaceSubnetMask=255.255.255.0
[1,0,0,0,0,0]1
DHCPServerEnable=1
[1,1,1,0,0,0]2
enable=0
MACAddress=bf:75:44:4c:dc:7e
externalIPAddress=0.0.0.0
defaultGateway=0.0.0.0
name=ipoe_1_d
subnetMask=0.0.0.0
DNSServers=0.0.0.0,0.0.0.0
[error]0

'''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkMRClientTest('', '')
        result = client.get_ipv4_status()

        self.assertIsInstance(result, IPv4Status)
        self.assertEqual(result.wan_macaddr, 'BF-75-44-4C-DC-7E')
        self.assertEqual(result.wan_ipv4_ipaddr, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_gateway, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_conntype, 'ipoe_1_d')
        self.assertEqual(result.wan_ipv4_netmask, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_pridns, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_snddns, '0.0.0.0')
        self.assertEqual(result.lan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result.lan_ipv4_ipaddr, '192.168.5.1')
        self.assertEqual(result.lan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(result.lan_ipv4_dhcp_enable, True)
        self.assertEqual(result.remote, None)

    def test_set_wifi(self) -> None:
        response = '''
[error]0

'''

        check_url = ''
        check_data = ''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                nonlocal check_url, check_data
                check_url = url
                check_data = data_str
                return 200, response

        client = TPLinkMRClientTest('', '')
        client.set_wifi(Connection.HOST_2G, True)

        self.assertIn('http:///cgi_gdpr?_=', check_url)
        self.assertEqual(check_data, '2\r\n[LAN_WLAN#1,1,0,0,0,0#0,0,0,0,0,0]0,1\r\nenable=1\r\n')

    def test_send_sms(self) -> None:
        response = '''
[error]0

'''

        check_url = ''
        check_data = ''

        class TPLinkMRClientTest(TPLinkMRClient):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                nonlocal check_url, check_data
                check_url = url
                check_data = data_str
                return 200, response

        client = TPLinkMRClientTest('', '')
        client.send_sms('534324724234', 'test sms')

        self.assertIn('http:///cgi_gdpr?_=', check_url)
        self.assertEqual(check_data, ('2\r\n[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\n'
                                      'to=534324724234\r\ntextContent=test sms\r\n'))


if __name__ == '__main__':
    main()
