from unittest import main, TestCase
from macaddress import EUI48
from ipaddress import IPv4Address
from tplinkrouterc6u import (
    TPLinkVX220Client,
    Connection,
    Firmware,
    Status,
    Device,
    ClientException,
)


class TestTPLinkVX220Client(TestCase):
    def test_supports(self) -> None:
        homepage = '<html><title>VX220-G2v</title><script src="cgi/getGDPRParm"></script></html>'

        class TPLinkVX220ClientTest(TPLinkVX220Client):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                if method == 'GET':
                    return 200, homepage
                raise ClientException()

        client = TPLinkVX220ClientTest('', '')
        result = client._verify_router()

        self.assertTrue(result)

    def test_supports_fail(self) -> None:
        homepage = '<html><title>Archer C6U</title><script src="cgi/getGDPRParm"></script></html>'

        class TPLinkVX220ClientTest(TPLinkVX220Client):
            def _request(self, url, method='POST', data_str=None, encrypt=False):
                if method == 'GET':
                    return 200, homepage
                raise ClientException()

        client = TPLinkVX220ClientTest('', '')
        result = client._verify_router()

        self.assertFalse(result)

    def test_firmware(self) -> None:
        response = ('{"data":{"hardwareVersion":"VX220-G2v v2.0 00000000","modelName":"VX220-G2v",'
                    '"softwareVersion":"0.9.0 2.0.0 v603c.0 Build 250328 Rel.7572n","stack":"0,0,0,0,0,0"},'
                    '"operation":"go","oid":"DEV2_DEV_INFO","success":true}')

        class TPLinkVX220ClientTest(TPLinkVX220Client):
            self._token = True

            def _request(self, url, method='POST', data_str=None, encrypt=False):
                return 200, response

        client = TPLinkVX220ClientTest('', '')
        result = client.get_firmware()

        self.assertIsInstance(result, Firmware)
        self.assertEqual(result.hardware_version, 'VX220-G2v v2.0 00000000')
        self.assertEqual(result.model, 'VX220-G2v')
        self.assertEqual(result.firmware_version, '0.9.0 2.0.0 v603c.0 Build 250328 Rel.7572n')

    def test_get_status(self) -> None:

        DEV2_ADT_LAN = ('{"data":[{"MACAddress":"b4:b0:24:aa:bb:cc","IPAddress":"192.168.1.1","stack":"1,0,0,0,0,0"}],'
                        '"operation":"gl","oid":"DEV2_ADT_LAN","success":true}')
        DEV2_ADT_WAN = ('{"data":[{"enable":"1","MACAddr":"C8-3A-35-DD-EE-FF","connIPv4Address":"100.64.1.10",'
                        '"connIPv4Gateway":"100.64.1.1","stack":"1,0,0,0,0,0"}],"operation":"gl",'
                        '"oid":"DEV2_ADT_WAN","success":true}')
        DEV2_ADT_WIFI_COMMON = ('{"data":[{"primaryEnable":"1","guestEnable":"0","stack":"1,0,0,0,0,0"},'
                                '{"primaryEnable":"1","guestEnable":"0","stack":"2,0,0,0,0,0"}],"operation":"gl",'
                                '"oid":"DEV2_ADT_WIFI_COMMON","success":true}')
        DEV2_HOST_ENTRY = ('{"data":[{"active":"1","X_TP_LanConnType":"0","physAddress":"AA-BB-CC-11-22-33",'
                           '"IPAddress":"192.168.1.100","hostName":"desktop","stack":"1,0,0,0,0,0"},'
                           '{"active":"1","X_TP_LanConnType":"1","physAddress":"DD-EE-FF-44-55-66",'
                           '"IPAddress":"192.168.1.101","hostName":"phone","stack":"2,0,0,0,0,0"},'
                           '{"active":"1","X_TP_LanConnType":"3","physAddress":"77-88-99-AA-BB-CC",'
                           '"IPAddress":"192.168.1.102","hostName":"laptop","stack":"3,0,0,0,0,0"}],"operation":"gl",'
                           '"oid":"DEV2_HOST_ENTRY","success":true}')
        DEV2_MEM_STATUS = ('{"data":{"total":"256000","free":"128000","stack":"0,0,0,0,0,0"},"operation":"go",'
                           '"oid":"DEV2_MEM_STATUS","success":true}')
        DEV2_PROC_STATUS = ('{"data":{"CPUUsage":"35","stack":"0,0,0,0,0,0"},"operation":"go",'
                            '"oid":"DEV2_PROC_STATUS","success":true}')

        class TPLinkVX220ClientTest(TPLinkVX220Client):
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

        client = TPLinkVX220ClientTest('', '')
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, 'C8-3A-35-DD-EE-FF')
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, 'B4-B0-24-AA-BB-CC')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '100.64.1.10')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.1.1')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.wan_ipv4_gateway, '100.64.1.1')
        self.assertEqual(status.wired_total, 1)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 3)
        self.assertEqual(status.guest_2g_enable, False)
        self.assertEqual(status.guest_5g_enable, False)
        self.assertEqual(status.iot_2g_enable, None)
        self.assertEqual(status.iot_5g_enable, None)
        self.assertEqual(status.wifi_2g_enable, True)
        self.assertEqual(status.wifi_5g_enable, True)
        self.assertEqual(status.wan_ipv4_uptime, None)
        self.assertGreaterEqual(status.mem_usage, 0)
        self.assertLessEqual(status.mem_usage, 1)
        self.assertGreaterEqual(status.cpu_usage, 0)
        self.assertLessEqual(status.cpu_usage, 1)
        self.assertEqual(len(status.devices), 3)
        self.assertIsInstance(status.devices[0], Device)
        self.assertEqual(status.devices[0].type, Connection.WIRED)
        self.assertEqual(status.devices[0].macaddr, 'AA-BB-CC-11-22-33')
        self.assertIsInstance(status.devices[0].macaddress, EUI48)
        self.assertEqual(status.devices[0].ipaddr, '192.168.1.100')
        self.assertIsInstance(status.devices[0].ipaddress, IPv4Address)
        self.assertEqual(status.devices[0].hostname, 'desktop')
        self.assertEqual(status.devices[0].packets_sent, None)
        self.assertEqual(status.devices[0].packets_received, None)
        self.assertIsInstance(status.devices[1], Device)
        self.assertEqual(status.devices[1].type, Connection.HOST_2G)
        self.assertEqual(status.devices[1].macaddr, 'DD-EE-FF-44-55-66')
        self.assertIsInstance(status.devices[1].macaddress, EUI48)
        self.assertEqual(status.devices[1].ipaddr, '192.168.1.101')
        self.assertIsInstance(status.devices[1].ipaddress, IPv4Address)
        self.assertEqual(status.devices[1].hostname, 'phone')
        self.assertEqual(status.devices[1].packets_sent, None)
        self.assertEqual(status.devices[1].packets_received, None)
        self.assertIsInstance(status.devices[2], Device)
        self.assertEqual(status.devices[2].type, Connection.HOST_5G)
        self.assertEqual(status.devices[2].macaddr, '77-88-99-AA-BB-CC')
        self.assertIsInstance(status.devices[2].macaddress, EUI48)
        self.assertEqual(status.devices[2].ipaddr, '192.168.1.102')
        self.assertIsInstance(status.devices[2].ipaddress, IPv4Address)
        self.assertEqual(status.devices[2].hostname, 'laptop')
        self.assertEqual(status.devices[2].packets_sent, None)
        self.assertEqual(status.devices[2].packets_received, None)


if __name__ == '__main__':
    main()
