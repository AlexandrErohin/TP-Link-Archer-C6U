from unittest import main, TestCase
from macaddress import EUI48
from ipaddress import IPv4Address
from tplinkrouterc6u import (
    TPLinkEXClient,
    Connection,
    Firmware,
    Status,
    Device,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
    ClientException,
)


class TestTPLinkEXClient(TestCase):
    def test_firmware(self) -> None:
        response = ('{"data":{"hardwareVersion":"EX511 v2.0 00000000","modelName":"EX511",'
                    '"softwareVersion":"0.7.0 3.0.0 v607e.0 Build 240930 Rel.11206n","stack":"0,0,0,0,0,0"},'
                    '"operation":"go","oid":"DEV2_DEV_INFO","success":true}')

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkEXClientTest('', '')
        result = client.get_firmware()

        self.assertIsInstance(result, Firmware)
        self.assertEqual(result.hardware_version, 'EX511 v2.0 00000000')
        self.assertEqual(result.model, 'EX511')
        self.assertEqual(result.firmware_version, '0.7.0 3.0.0 v607e.0 Build 240930 Rel.11206n')

    def test_get_status_with_5G(self) -> None:

        DEV2_ADT_LAN = ('{"data":[{"MACAddress":"a0:28:84:de:dd:5c","IPAddress":"192.168.4.1","stack":"1,0,0,0,0,0"}],'
                        '"operation":"gl","oid":"DEV2_ADT_LAN","success":true}')
        DEV2_ADT_WAN = ('{"data":[{"enable":"1","MACAddr":"BF-75-44-4C-DC-9E","connIPv4Address":"192.168.30.55",'
                        '"connIPv4Gateway":"192.168.30.1","stack":"1,0,0,0,0,0"}],"operation":"gl",'
                        '"oid":"DEV2_ADT_WAN","success":true}')
        DEV2_ADT_WIFI_COMMON = ('{"data":[{"primaryEnable":"1","guestEnable":"0","stack":"1,0,0,0,0,0"},'
                                '{"primaryEnable":"0","guestEnable":"1","stack":"2,0,0,0,0,0"}],"operation":"gl",'
                                '"oid":"DEV2_ADT_WIFI_COMMON","success":true}')
        DEV2_HOST_ENTRY = ('{"data":[{"active":"1","X_TP_LanConnType":"0","physAddress":"66-E2-02-BD-B5-1B",'
                           '"IPAddress":"192.168.30.10","hostName":"host1","stack":"1,0,0,0,0,0"},'
                           '{"active":"1","X_TP_LanConnType":"1","physAddress":"F4-A3-86-2D-41-B5",'
                           '"IPAddress":"192.168.30.11","hostName":"host2","stack":"2,0,0,0,0,0"}],"operation":"gl",'
                           '"oid":"DEV2_HOST_ENTRY","success":true}')
        DEV2_MEM_STATUS = ('{"data":{"total":"192780","free":"78400","stack":"0,0,0,0,0,0"},"operation":"go",'
                           '"oid":"DEV2_MEM_STATUS","success":true}')
        DEV2_PROC_STATUS = ('{"data":{"CPUUsage":"47","stack":"0,0,0,0,0,0"},"operation":"go",'
                            '"oid":"DEV2_PROC_STATUS","success":true}')

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                if 'DEV2_ADT_LAN' in data_str:
                    return 200, DEV2_ADT_LAN
                elif 'DEV2_ADT_WAN' in data_str:
                    return 200, DEV2_ADT_WAN
                elif 'DEV2_ADT_WIFI_COMMON' in data_str:
                    return 200, DEV2_ADT_WIFI_COMMON
                elif 'DEV2_HOST_ENTRY' in data_str:
                    return 200, DEV2_HOST_ENTRY
                elif 'DEV2_MEM_STATUS' in data_str:
                    return 200, DEV2_MEM_STATUS
                elif 'DEV2_PROC_STATUS' in data_str:
                    return 200, DEV2_PROC_STATUS
                raise ClientException()

        client = TPLinkEXClientTest('', '')
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
        self.assertGreaterEqual(status.mem_usage, 0)
        self.assertLessEqual(status.mem_usage, 1)
        self.assertGreaterEqual(status.cpu_usage, 0)
        self.assertLessEqual(status.cpu_usage, 1)
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
        self.assertEqual(status.devices[1].type, Connection.HOST_2G)
        self.assertEqual(status.devices[1].macaddr, 'F4-A3-86-2D-41-B5')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.30.11')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'host2')
        self.assertEqual(status.devices[1].packets_sent, None)  # TODO
        self.assertEqual(status.devices[1].packets_received, None)  # TODO

    def test_get_ipv4_reservations(self) -> None:

        response = ('{"data":[{"enable":"1","chaddr":"bf:75:44:4c:dc:9e","yiaddr":"192.168.8.21",'
                    '"stack":"1,1,0,0,0,0"}],"operation":"gl","oid":"DEV2_DHCPV4_POOL_STATICADDR","success":true}')

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkEXClientTest('', '')
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
        response = '{"data":[],"operation":"gl","oid":"DEV2_DHCPV4_POOL_STATICADDR","success":true}'

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkEXClientTest('', '')
        result = client.get_ipv4_reservations()

        self.assertEqual(len(result), 0)

    def test_get_ipv4_dhcp_leases_no_leases(self) -> None:

        response = '{"data":[],"operation":"gl","oid":"DEV2_HOST_ENTRY","success":true}'

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkEXClientTest('', '')
        result = client.get_ipv4_dhcp_leases()

        self.assertEqual(len(result), 0)

    def test_get_ipv4_dhcp_leases(self) -> None:

        response = ('{"data":[{"alias":"","physAddress":"bf:75:44:4c:dc:9e","IPAddress":"192.168.32.175",'
                    '"addressSource":"Static","leaseTimeRemaining":"85841","X_TP_IPv6Address":"",'
                    '"X_TP_IPv6LinkLocal":"","layer1Interface":"",'
                    '"X_TP_Layer2Interface":"Device.WiFi.AccessPoint.1.","vendorClassID":"","clientID":"",'
                    '"hostName":"name1","interfaceType":"Wi-Fi","X_TP_LanConnType":"1","X_TP_LanConnDev":"br0",'
                    '"active":"1","IPv4AddressNumberOfEntries":"0","X_TP_Vendor":"","X_TP_ClientType":"Other",'
                    '"X_TP_DevphyAddress":"","IPv6AddressNumberOfEntries":"0","X_TP_NetworkReadyTime":"0",'
                    '"stack":"1,0,0,0,0,0"}],"operation":"gl","oid":"DEV2_HOST_ENTRY","success":true}')

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkEXClientTest('', '')
        result = client.get_ipv4_dhcp_leases()

        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], IPv4DHCPLease)
        self.assertEqual(result[0].macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result[0].ipaddr, '192.168.32.175')
        self.assertEqual(result[0].hostname, 'name1')
        self.assertEqual(result[0].lease_time, '23:50:41')

    def test_get_ipv4_dhcp_leases_permanent(self) -> None:

        response = ('{"data":[{"alias":"","physAddress":"bf:75:44:4c:dc:9e","IPAddress":"192.168.32.175",'
                    '"addressSource":"Static","leaseTimeRemaining":"0","X_TP_IPv6Address":"",'
                    '"X_TP_IPv6LinkLocal":"","layer1Interface":"","X_TP_Layer2Interface":"Device.WiFi.AccessPoint.1.",'
                    '"vendorClassID":"","clientID":"","hostName":"name1","interfaceType":"Wi-Fi",'
                    '"X_TP_LanConnType":"1","X_TP_LanConnDev":"br0","active":"1","IPv4AddressNumberOfEntries":"0",'
                    '"X_TP_Vendor":"","X_TP_ClientType":"Other","X_TP_DevphyAddress":"",'
                    '"IPv6AddressNumberOfEntries":"0","X_TP_NetworkReadyTime":"0","stack":"1,0,0,0,0,0"},'
                    '{"alias":"","physAddress":"a0:28:84:de:dd:5c","IPAddress":"192.168.32.176",'
                    '"addressSource":"Static","leaseTimeRemaining":"86372","X_TP_IPv6Address":"",'
                    '"X_TP_IPv6LinkLocal":"","layer1Interface":"","X_TP_Layer2Interface":"Device.WiFi.AccessPoint.1.",'
                    '"vendorClassID":"","clientID":"","hostName":"name2","interfaceType":"Wi-Fi",'
                    '"X_TP_LanConnType":"1","X_TP_LanConnDev":"br0","active":"1","IPv4AddressNumberOfEntries":"0",'
                    '"X_TP_Vendor":"","X_TP_ClientType":"Other","X_TP_DevphyAddress":"",'
                    '"IPv6AddressNumberOfEntries":"0","X_TP_NetworkReadyTime":"0","stack":"1,0,0,0,0,0"}],'
                    '"operation":"gl","oid":"DEV2_HOST_ENTRY","success":true}')

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkEXClientTest('', '')
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

        DEV2_ADT_LAN = ('{"data":[{"MACAddress":"bf:75:44:4c:dc:9e","IPAddress":"192.168.5.1",'
                        '"IPSubnetMask":"255.255.255.0","DHCPv4Enable":"1","stack":"1,0,0,0,0,0"}],'
                        '"operation":"gl","oid":"DEV2_ADT_LAN","success":true}')
        DEV2_ADT_WAN = ('{"data":[{"enable":"1","MACAddr":"a0:28:84:de:dd:5c","connIPv4Address":"10.10.11.5",'
                        '"connIPv4Gateway":"11.11.11.11","name":"ipoe_0_0_d","connIPv4SubnetMask":"1.1.1.1",'
                        '"connIPv4DnsServer":"8.8.8.8,8.8.4.4","stack":"1,0,0,0,0,0"}],"operation":"gl",'
                        '"oid":"DEV2_ADT_WAN","success":true}')

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                if 'DEV2_ADT_LAN' in data_str:
                    return 200, DEV2_ADT_LAN
                elif 'DEV2_ADT_WAN' in data_str:
                    return 200, DEV2_ADT_WAN
                raise ClientException()

        client = TPLinkEXClientTest('', '')
        result = client.get_ipv4_status()

        self.assertIsInstance(result, IPv4Status)
        self.assertEqual(result.wan_macaddr, 'A0-28-84-DE-DD-5C')
        self.assertEqual(result.wan_ipv4_ipaddr, '10.10.11.5')
        self.assertEqual(result.wan_ipv4_gateway, '11.11.11.11')
        self.assertEqual(result.wan_ipv4_conntype, 'ipoe_0_0_d')
        self.assertEqual(result.wan_ipv4_netmask, '1.1.1.1')
        self.assertEqual(result.wan_ipv4_pridns, '8.8.8.8')
        self.assertEqual(result.wan_ipv4_snddns, '8.8.4.4')
        self.assertEqual(result.lan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result.lan_ipv4_ipaddr, '192.168.5.1')
        self.assertEqual(result.lan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(result.lan_ipv4_dhcp_enable, True)
        self.assertEqual(result.remote, None)

    def test_get_ipv4_status_one_wlan(self) -> None:

        DEV2_ADT_LAN = ('{"data":[{"MACAddress":"bf:75:44:4c:dc:9e","IPAddress":"192.168.5.1",'
                        '"IPSubnetMask":"255.255.255.0","DHCPv4Enable":"1","stack":"1,0,0,0,0,0"}],'
                        '"operation":"gl","oid":"DEV2_ADT_LAN","success":true}')
        DEV2_ADT_WAN = ('{"data":[{"enable":"1","MACAddr":"ba:7a:a4:4a:dc:7e","connIPv4Address":"0.0.0.0",'
                        '"connIPv4Gateway":"0.0.0.0","name":"ipoe_0_0_d","connIPv4SubnetMask":"0.0.0.0",'
                        '"connIPv4DnsServer":"0.0.0.0,0.0.0.0","stack":"1,0,0,0,0,0"}],"operation":"gl",'
                        '"oid":"DEV2_ADT_WAN","success":true}')

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                if 'DEV2_ADT_LAN' in data_str:
                    return 200, DEV2_ADT_LAN
                elif 'DEV2_ADT_WAN' in data_str:
                    return 200, DEV2_ADT_WAN
                raise ClientException()

        client = TPLinkEXClientTest('', '')
        result = client.get_ipv4_status()

        self.assertIsInstance(result, IPv4Status)
        self.assertEqual(result.wan_macaddr, 'BA-7A-A4-4A-DC-7E')
        self.assertEqual(result.wan_ipv4_ipaddr, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_gateway, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_conntype, 'ipoe_0_0_d')
        self.assertEqual(result.wan_ipv4_netmask, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_pridns, '0.0.0.0')
        self.assertEqual(result.wan_ipv4_snddns, '0.0.0.0')
        self.assertEqual(result.lan_macaddr, 'BF-75-44-4C-DC-9E')
        self.assertEqual(result.lan_ipv4_ipaddr, '192.168.5.1')
        self.assertEqual(result.lan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(result.lan_ipv4_dhcp_enable, True)
        self.assertEqual(result.remote, None)

    def test_set_wifi(self) -> None:
        response = '{"success":true, "errorcode":0}'

        check_url = ''
        check_data = ''

        class TPLinkEXClientTest(TPLinkEXClient):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                nonlocal check_url, check_data
                check_url = url
                check_data = data_str
                return 200, response

        client = TPLinkEXClientTest('', '')
        client.set_wifi(Connection.HOST_2G, True)

        self.assertIn('http:///cgi_gdpr?9?_=', check_url)
        self.assertEqual(check_data, '{"data":{"stack":"1,0,0,0,0,0","pstack":"0,0,0,0,0,0",'
                                     '"primaryEnable":"1"},"operation":"so","oid":"DEV2_ADT_WIFI_COMMON"}')


if __name__ == '__main__':
    main()
