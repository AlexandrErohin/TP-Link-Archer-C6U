from ipaddress import IPv4Address
from typing import List
from unittest import main, TestCase

from macaddress import EUI48

from tplinkrouterc6u import (
    TplinkC3200Router,
    Connection,
    Status,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
)


class TestTPLinkC3200Router(TestCase):


    #  Testing the merge_response method
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
        client = TplinkC3200Router('', '')
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
        client = TplinkC3200Router('', '')
        result = client._merge_response(response)

        self.assertEqual(result, [])


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

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
        status = client.get_status()

        self.assertEqual(status.wan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(status.lan_macaddr, 'A0-28-84-DE-DD-5C')
        self.assertEqual(status.wan_ipv4_addr, '192.168.30.55')
        self.assertEqual(status.lan_ipv4_addr, '192.168.4.1')
        self.assertEqual(status.wan_ipv4_gateway, '192.168.30.1')
        self.assertEqual(status.conn_type, 'ipoe_1_d')
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

    def test_get_status_C3200(self) -> None:
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

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
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

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
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
chaddr=24:11:32:11:E4:0C
yiaddr=192.1.1.102
description=SAN
[1,3,0,0,0,0]0
enable=1
chaddr=D4:6A:6A:B9:F6:74
yiaddr=192.1.1.103
description=scan
[1,4,0,0,0,0]0
enable=1
chaddr=CC:32:52:44:62:3E
yiaddr=192.1.1.110
description=HS 110 Energie
[1,5,0,0,0,0]0
enable=1
chaddr=50:D4:F7:7A:89:23
yiaddr=192.1.1.109
description=hs124_box
[1,7,0,0,0,0]0
enable=1
chaddr=24:0C:29:E3:A6:89
yiaddr=192.1.1.120
description=vmdebiandev
[1,9,0,0,0,0]0
enable=1
chaddr=24:0C:29:48:15:C8
yiaddr=192.1.1.121
description=vmdebiantest
[1,10,0,0,0,0]0
enable=1
chaddr=24:04:20:2B:7A:D3
yiaddr=192.1.1.97
description=Radio
[1,11,0,0,0,0]0
enable=1
chaddr=F8:A2:6D:28:ED:06
yiaddr=192.1.1.96
description=imprimante
[1,12,0,0,0,0]0
enable=1
chaddr=B8:8A:60:D3:7A:17
yiaddr=192.1.1.125
description=XXX WIFI
[1,13,0,0,0,0]0
enable=1
chaddr=C8:6F:76:86:95:76
yiaddr=192.1.1.126
description=XXX FIXE ETHERNET
[1,14,0,0,0,0]0
enable=1
chaddr=D8:4D:17:1C:7E:41
yiaddr=192.1.1.111
description=hs124_SqBox
[1,15,0,0,0,0]0
enable=1
chaddr=AC:84:C6:D3:F6:40
yiaddr=192.1.1.112
description=HS124_Garage
[1,16,0,0,0,0]0
enable=1
chaddr=C4:6F:BF:6B:09:52
yiaddr=192.1.1.130
description=Shelly SDB
[1,17,0,0,0,0]0
enable=1
chaddr=C4:6F:BF:6B:89:B8
yiaddr=192.1.1.131
description=Shelly 2
[1,18,0,0,0,0]0
enable=1
chaddr=74:DA:88:7C:E6:4B
yiaddr=192.1.1.113
description=HS110 ChauffeEau
[1,19,0,0,0,0]0
enable=1
chaddr=20:F8:3D:01:6F:2F
yiaddr=192.1.1.107
description=homeassistant
[1,20,0,0,0,0]0
enable=1
chaddr=CC:32:52:F1:C1:FE
yiaddr=192.1.1.114
description=HS124 Sqz SDB
[error]0

'''

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
        result = client.get_ipv4_reservations()

        # IPv4Reservation(_macaddr=EUI48('C4-6F-BF-6B-89-B8'), _ipaddr=IPv4Address('192.1.1.131'), hostname='Shelly 2', enabled=True)
        self.assertEqual(len(result), 17)
        self.assertIsInstance(result[13], IPv4Reservation)
        self.assertEqual(result[13].macaddr, 'C4-6F-BF-6B-89-B8')
        self.assertEqual(result[13].ipaddr, '192.1.1.131')
        self.assertEqual(result[13].hostname, 'Shelly 2')
        self.assertEqual(result[13].enabled, True)

    def test_get_ipv4_reservations_no_reservations(self) -> None:
        response = '''
[error]0

'''

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
        result = client.get_ipv4_reservations()

        self.assertEqual(len(result), 0)

    def test_get_ipv4_dhcp_leases_no_leases(self) -> None:
        response = '''
[error]0

'''

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
        result = client.get_ipv4_dhcp_leases()

        self.assertEqual(len(result), 0)

    def test_get_ipv4_dhcp_leases(self) -> None:
        response = '''
[1,0,0,0,0,0]0
IPAddress=192.1.1.5
MACAddress=23:DC:FF:45:61:25
hostName=Unknown
leaseTimeRemaining=86361
[2,0,0,0,0,0]0
IPAddress=192.1.1.2
MACAddress=24:04:20:2E:3F:90
hostName=Radio
leaseTimeRemaining=52243
[3,0,0,0,0,0]0
IPAddress=192.1.1.14
MACAddress=F4:6D:3F:09:11:4F
hostName=IFP325133986
leaseTimeRemaining=86360
[4,0,0,0,0,0]0
IPAddress=192.1.1.102
MACAddress=24:11:32:11:E4:0C
hostName=SAN
leaseTimeRemaining=-1
[5,0,0,0,0,0]0
IPAddress=192.1.1.24
MACAddress=04:EC:D8:44:6A:4E
hostName=jeremy-msi
leaseTimeRemaining=86371
[6,0,0,0,0,0]0
IPAddress=192.1.1.8
MACAddress=E4:4D:36:84:24:47
hostName=Samuel_Laptop
leaseTimeRemaining=86342
[7,0,0,0,0,0]0
IPAddress=192.1.1.113
MACAddress=74:DA:88:7C:E6:4B
hostName=HS110
leaseTimeRemaining=-1
[8,0,0,0,0,0]0
IPAddress=192.1.1.111
MACAddress=D8:4D:17:1C:7E:41
hostName=HS124
leaseTimeRemaining=-1
[9,0,0,0,0,0]0
IPAddress=192.1.1.103
MACAddress=D4:6A:6A:B9:F6:74
hostName=BRWD46A67A9F674
leaseTimeRemaining=-1
[10,0,0,0,0,0]0
IPAddress=192.1.1.4
MACAddress=DA:25:E8:42:61:62
hostName=Portable2
leaseTimeRemaining=82550
[11,0,0,0,0,0]0
IPAddress=192.1.1.6
MACAddress=06:52:77:4D:6D:7B
hostName=iPhone
leaseTimeRemaining=84961
[12,0,0,0,0,0]0
IPAddress=192.1.1.10
MACAddress=D8:FC:93:1A:4A:AF
hostName=jeremy-W54-55SU1-SUW
leaseTimeRemaining=79549
[13,0,0,0,0,0]0
IPAddress=192.1.1.131
MACAddress=C4:6F:BF:6B:89:B8
hostName=shellyswitch25-
leaseTimeRemaining=-1
[14,0,0,0,0,0]0
IPAddress=192.1.1.130
MACAddress=C4:6F:BF:6B:09:52
hostName=shellyswitch25-
leaseTimeRemaining=-1
[15,0,0,0,0,0]0
IPAddress=192.1.1.18
MACAddress=24:04:20:2E:60:AD
hostName=Radio
leaseTimeRemaining=86368
[16,0,0,0,0,0]0
IPAddress=192.1.1.11
MACAddress=42:FD:4D:23:26:9C
hostName=Portable1
leaseTimeRemaining=7A826
[17,0,0,0,0,0]0
IPAddress=192.1.1.109
MACAddress=50:D4:F7:7A:89:23
hostName=HS124
leaseTimeRemaining=-1
[18,0,0,0,0,0]0
IPAddress=192.1.1.112
MACAddress=AC:84:C6:D3:F6:40
hostName=HS124
leaseTimeRemaining=-1
[19,0,0,0,0,0]0
IPAddress=192.1.1.114
MACAddress=CC:32:52:F1:C1:FE
hostName=HS124
leaseTimeRemaining=-1
[20,0,0,0,0,0]0
IPAddress=192.1.1.15
MACAddress=F8:6F:3D:14:70:45
hostName=COM-MID1
leaseTimeRemaining=54031
[21,0,0,0,0,0]0
IPAddress=192.1.1.16
MACAddress=A2:42:58:24:80:D2
hostName=Portable2
leaseTimeRemaining=78484
[22,0,0,0,0,0]0
IPAddress=192.1.1.17
MACAddress=E8:6D:52:23:39:72
hostName=repeteur
leaseTimeRemaining=70825
[23,0,0,0,0,0]0
IPAddress=192.1.1.97
MACAddress=24:04:20:2B:7A:D3
hostName=Radio
leaseTimeRemaining=-1
[24,0,0,0,0,0]0
IPAddress=192.1.1.17
MACAddress=E8:6D:52:23:39:73
hostName=Unknown
leaseTimeRemaining=0
[25,0,0,0,0,0]0
IPAddress=192.1.1.107
MACAddress=20:F8:3D:01:6F:2F
hostName=Unknown
leaseTimeRemaining=0
[error]0

'''

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
        result: List[IPv4DHCPLease]
        result = client.get_ipv4_dhcp_leases()

        # #20 :  IPv4DHCPLease(_macaddr=EUI48('A2-42-58-24-80-D2'), _ipaddr=IPv4Address('192.1.1.16'), hostname='Portable2', lease_time='21:48:04')
        self.assertEqual(len(result), 25)
        self.assertIsInstance(result[20], IPv4DHCPLease)
        self.assertEqual(result[20].macaddr, 'A2-42-58-24-80-D2')
        self.assertEqual(result[20].ipaddr, '192.1.1.16')
        self.assertEqual(result[20].hostname, 'Portable2')
        self.assertEqual(result[20].lease_time, '21:48:04')

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

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
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

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
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

    def test_get_ipv4_status_empty(self) -> None:
        response = '''
[1,1,0,0,0,0]0
[1,1,0,0,0,0]1
[1,1,1,0,0,0]2
[2,1,1,0,0,0]2
[error]0

'''

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
        result = client.get_ipv4_status()

        self.assertIsInstance(result, IPv4Status)
        self.assertEqual(result.lan_macaddr, '00-00-00-00-00-00')
        self.assertEqual(result.wan_ipv4_conntype, '')
        self.assertEqual(result.lan_ipv4_ipaddr, '0.0.0.0')
        self.assertEqual(result.lan_ipv4_netmask, '0.0.0.0')
        self.assertEqual(result.lan_ipv4_dhcp_enable, False)

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

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                return 200, response

        client = TplinkC3200RouterTest('', '')
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

        class TplinkC3200RouterTest(TplinkC3200Router):
            def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
                nonlocal check_url, check_data
                check_url = url
                check_data = data_str
                return 200, response

        client = TplinkC3200RouterTest('', '')
        client.set_wifi(Connection.HOST_2G, True)

        self.assertIn('http:///cgi?2', check_url)
        self.assertEqual(check_data, '[LAN_WLAN#1,1,0,0,0,0#0,0,0,0,0,0]0,1\r\nenable=1\r\n')


if __name__ == '__main__':
    main()
