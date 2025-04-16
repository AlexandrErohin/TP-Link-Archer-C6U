from unittest import main, TestCase
from ipaddress import IPv4Address
from macaddress import EUI48
from tplinkrouterc6u.common.dataclass import Firmware, Status
from tplinkrouterc6u.common.dataclass import IPv4Status, IPv4Reservation, IPv4DHCPLease
from tplinkrouterc6u import ClientError
from tplinkrouterc6u.client.wdr import TplinkWDRRouter

_NETWAN = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar wanTypeDetectInfoArray = '
    + "new Array(\n1, 0, 4500, \n0,0 );\n</SCRIPT>\n"
    + '<SCRIPT language="javascript" type="text/javascript">\nvar dhcpInf = new Array(\n1,\n'
    + '0,\n1,\n0,\n0,\n0,\n0,\n0,\n"",\n"",\n0,\n0,\n"",\n"192.168.0.129",\n"255.255.255.0",\n'
    + '"192.168.0.1",\n1,\n0,\n1500,\n0,\n"8.8.8.8",\n1,\n"8.8.4.4",\n0,\n0,\n0,\n"TL-WDR3600",\n0,0 );\n</SCRIPT>\n'
    + '<SCRIPT language="javascript" type="text/javascript">\nvar wantypeinfo = new Array(\n6,\n0,\n'
    + '"WanDynamicIpCfgRpm.htm",\n1,\n"WanStaticIpCfgRpm.htm",\n'
    + '2,\n"PPPoECfgRpm.htm",\n5,\n"BPACfgRpm.htm",\n6,\n"L2TPCfgRpm.htm",\n7,\n"PPTPCfgRpm.htm",\n0,0 );\n</SCRIPT>'
)
_NETLAN = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar lanPara = new Array(\n"C4-6E-1F-41-67-C0",\n'
    + '"192.168.1.254",\n2,\n"255.255.255.0",\n1,\n0,0 );\n</SCRIPT>'
)

_W24STA = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar wlanHostPara = new Array(\n1, 1, 8, 5000, 4,\n'
    + '0,0);\n</SCRIPT>\n<SCRIPT language="javascript" type="text/javascript">\nvar hostList = new Array(\n'
    + '"D0-BD-53-57-3E-4A", 1, 170893827, 0,\n"08-16-AC-03-E2-FA", 1, 873409583, 0,\n"F8-F1-E8-CD-0A-CF", 1, '
    + '240958643, 0,\n"ED-49-92-1A-1D-D7", 1, 358743698, 0,\n"0E-50-99-5D-9A-D5", 1, 572346959, 0,\n0,0 );\n</SCRIPT>'
)
_W50STA = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar wlanHostPara = new Array(\n1, 1, 8, 5000, 4,\n'
    + '0,0 );\n</SCRIPT>\n<SCRIPT language="javascript" type="text/javascript">\nvar hostList = new Array(\n'
    + '"50-A6-FC-6D-EB-D3", 1, 708938274, 0,\n"6A-D0-5F-2A-FA-2D", 1, 287340958, 0,\n"DA-69-2D-59-B3-FA", 1'
    + ", 540958641, 0,\n0,0 );\n</SCRIPT>"
)

_WLANGUEST = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar guestNetworkBandwidthInf = '
    + "new Array(\n"
    + '0,\n1000000,\n1000000,\n1024,\n1024,\n1,\n0,0);\n</SCRIPT>\n<SCRIPT language="javascript" '
    + 'type="text/javascript">'
    + '\nvar guestNetAccTime2gInf = new Array(\n1,\n1,\n0,\n0,\n0,\n1,\n0,\n0,\n0,\n0,\n0,\n0,\n0,\n1,\n"",\n"",\n'
    + "0,0 );"
    + '\n</SCRIPT>\n<SCRIPT language="javascript" type="text/javascript">\nvar guestNetAccTime5gInf = new Array(\n'
    + '1,\n0,\n0,\n0,\n0,\n1,\n0,\n0,\n0,\n0,\n0,\n0,\n0,\n1,\n"",\n"",\n0,0 );\n</SCRIPT>\n'
    + '<SCRIPT language="javascript" type="text/javascript">\nvar guestNetworkInf = '
    + 'new Array(\n1, 1, 1, 0, "Pegasus", '
    + '"Pegasus", 1, 1, 3, 3, "333", "333", 0, 0, "p4ssw0rd", "p4ssw0rd", '
    + "0, 0, 0, 0, 3, 3, 1, 1, 5, 8, 0, \n0,0 );\n"
    + "</SCRIPT>"
)

_DHCPCFG = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar DHCPPara = new Array(\n1,\n"192.168.1.129",\n'
    + '"192.168.1.192",\n120,\n"192.168.1.254",\n"internal.lan",\n"8.8.8.8",\n"8.8.4.4",\n0,\n0,0 );\n</SCRIPT>'
)

_DHCPLEASES = (
    '<SCRIPT language="javascript" type="text/javascript">var DHCPDynList = new Array(\n"aliquam",'
    + '"A9-A8-2B-F7-9F-5D","192.168.1.123","Permanent",\n"pharetra","B3-A5-1E-C3-92-A9","192.168.1.163","Permanent",\n'
    + '"ligula","71-34-47-FD-DE-84","192.168.1.165","Permanent",\n"vulputate","46-5F-5F-27-23-9F","192.168.1.103",'
    + '"Permanent",\n"amet","86-9F-53-91-04-2B","192.168.1.72","Permanent",\n"volutpat","FA-5C-6F-87-A3-5A",'
    + '"192.168.1.43",'
    + '"Permanent",\n"eget","C4-ED-6C-B6-F6-B9","192.168.1.112","Permanent",\n"ante","FF-C1-A3-93-C8-E6",'
    + '"192.168.1.38",'
    + '"Permanent",\n"pellentesque","E3-5E-59-2E-CF-AD","192.168.1.148","Permanent",\n"metus","AE-15-51-37-0E-9E",'
    + '"192.168.1.178","Permanent",\n0,0 );\n</SCRIPT>\n<SCRIPT language="javascript" type="text/javascript">\n'
    + "var DHCPDynPara = new Array(\n10,\n4,\n0,0 );\n</SCRIPT>"
)

_DHCPRESERVES = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar dhcpList = new Array(\n"9B-FA-04-D8-AB-8D",'
    + '"192.168.1.56",1,\n"EE-7C-6B-B6-05-2F","192.168.1.51",1,\n"09-51-B3-0B-92-01","192.168.1.21",1,\n'
    + '"49-6F-72-CD-68-5D","192.168.1.25",1,\n"DF-24-38-C1-FE-BB","192.168.1.51",1,\n"1A-08-6C-52-31-3D",'
    + '"192.168.1.22",1,\n"DE-E4-DF-9A-AD-0D","192.168.1.17",1,\n"DF-F2-CB-FE-46-15","192.168.1.26",1,\n'
    + '0,0 )\n</SCRIPT>\n<SCRIPT language="javascript" type="text/javascript">var DHCPStaticPara = '
    + "new Array(\n1,\n1,\n8,\n1,\n8,\n0,0 );\n</SCRIPT>"
)

ABSTRACT_STATUS = (
    '<SCRIPT language="javascript" type="text/javascript">\nvar statusPara = new Array(\n1,\n1,\n1,\n'
    + '22,\n20000,\n1468171,\n"3.13.34 Build 130909 Rel.53148n ",\n"WDR3600 v1 00000000",\n6732336,\n0, 0);\n'
    + '</SCRIPT>\n'
    + '<SCRIPT language="javascript" type="text/javascript">\nvar lanPara = new Array(\n"C4-6E-1F-41-67-C0", '
    + '"192.168.1.254", "255.255.255.0",\n0, 0);\n</SCRIPT>\n<SCRIPT language="javascript" type="text/javascript">\n'
    + 'var wlanPara = new Array(\n1,\n"testSSID24",\n15,\n5,\n"C4-6E-1F-41-67-BF",\n"192.168.1.254",\n2,\n8,\n71,\n6,\n'
    + '6,\n0, 0);\n</SCRIPT>\n<SCRIPT language="javascript" type="text/javascript">\nvar wlan5GPara = new Array(\n1,\n'
    + '"testSSID",\n15,\n8,\n"C4-6E-1F-41-67-C0",\n"192.168.1.254",\n2,\n8,\n83,\n36,\n6,\n0, 0);\n</SCRIPT>\n'
    + '<SCRIPT language="javascript" type="text/javascript">\nvar statistList = '
    + "new Array(\n1129349328, 3900411475, 200068023, 165562287,\n0, 0);\n</SCRIPT>\n"
    + '<SCRIPT language="javascript" type="text/javascript">\nvar wanPara = new Array(\n4, '
    + '"C4-6E-1F-41-67-C1", "192.168.0.129", 1, "255.255.255.0", 0, 0, "192.168.0.1", 1, 1, 0, '
    + '"8.8.8.8 , 8.8.4.4", "", 0, 0, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0 , 0.0.0.0", '
    + "0, 0, 0, 0, 0,\n0, 0);\n</SCRIPT>"
)

ABSTRACT_NETWORK = {
    "netWan": _NETWAN,
    "netLan": _NETLAN,
    "w24stations": _W24STA,
    "w50stations": _W50STA,
    "wgsettings": _WLANGUEST,
    "dhcpconfig": _DHCPCFG,
    "dhcplease": _DHCPLEASES,
    "dhcpreserve": _DHCPRESERVES,
}


class ResponseMock:
    def __init__(self, text: str, status_code=0):
        self.content = text.encode("utf8")
        self.status_code = status_code
        self.headers: dict = {}


class TplinkWDRRouterTest(TplinkWDRRouter):
    response = ""

    def request(
        self,
        section: str,
        data: str,
        ignore_response: bool = False,
        ignore_errors: bool = False,
    ) -> str | dict | None:
        # only a test, so no extra headers
        # Responses
        sections = "summary,status,"
        sections += "netWan,netLan,dualBand,"
        sections += "w24settings,w24wps,w24sec,w24adv,w24stations,"
        sections += "w50settings,w50wps,w50sec,w50adv,w50stations,"
        sections += "wgsettings,wgshare,dhcpconfig,dhcplease,dhcpreserve,"
        sections += "portFwd,sysroute,upnpFwd"

        section_list = sections.split(",")

        if ignore_response:
            return None
        elif section == "check":
            resp = ResponseMock("", 200)
            resp.headers["www-authenticate"] = (
                'Basic realm="TP-LINK Wireless Dual Band Gigabit Router WDR3600"'
            )
            return resp
        elif section in section_list:
            if section in ["summary", "status"]:
                return ResponseMock(ABSTRACT_STATUS).content
            elif section in ["w24stations", "w50stations", "dhcpreserve"]:
                return ResponseMock(ABSTRACT_NETWORK[section]).content
            elif section in [
                "netLan",
                "netWan",
                # 'w24stations',
                # 'w50stations',
                "wgsettings",
                "dhcpconfig",
                "dhcplease",
                # 'dhcpreserve',
            ]:
                return ResponseMock(ABSTRACT_NETWORK[section]).content
            else:
                return ""
                # raise ClientError (f'Section {section} not allowed')

        else:
            error = ""
            error = (
                (
                    "WDRRouter - {} - Response with error; Request {} - Response {}".format(
                        self.__class__.__name__, section, data
                    )
                )
                if not error
                else error
            )
            if self._logger:
                self._logger.debug(error)

            raise ClientError(error)


class TestTPLinkWDRClient(TestCase):

    def test_supports(self) -> None:
        client = TplinkWDRRouterTest("", "")
        # client.response =  ResponseMock(ABSTRACT_STATUS)
        supports = client.supports()
        self.assertTrue(supports)

    def test_get_firmware(self) -> None:

        client = TplinkWDRRouterTest("", "")
        client.response = ResponseMock(ABSTRACT_STATUS)
        firmware = client.get_firmware()

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, "WDR3600 v1 00000000")
        self.assertEqual(firmware.model, "WDR3600")
        self.assertEqual(
            firmware.firmware_version.strip(), "3.13.34 Build 130909 Rel.53148n"
        )

    def test_get_ipv4(self) -> None:

        client = TplinkWDRRouterTest("", "")
        ipv4status: IPv4Status = IPv4Status()
        ipv4status = client.get_ipv4_status()

        self.assertIsInstance(ipv4status, IPv4Status)
        self.assertEqual(ipv4status._wan_macaddr, EUI48("C4-6E-1F-41-67-C1"))
        self.assertEqual(
            IPv4Address(ipv4status.wan_ipv4_ipaddr), IPv4Address("192.168.0.129")
        )
        self.assertEqual(
            IPv4Address(ipv4status.wan_ipv4_gateway), IPv4Address("192.168.0.1")
        )
        self.assertEqual(ipv4status.wan_ipv4_conntype, "Dynamic IP")
        self.assertEqual(
            IPv4Address(ipv4status.wan_ipv4_netmask), IPv4Address("255.255.255.0")
        )
        self.assertEqual(
            IPv4Address(ipv4status.wan_ipv4_pridns), IPv4Address("0.0.0.0")
        )
        self.assertEqual(
            IPv4Address(ipv4status.wan_ipv4_snddns), IPv4Address("0.0.0.0")
        )
        self.assertEqual(ipv4status._lan_macaddr, EUI48("C4-6E-1F-41-67-C0"))
        self.assertEqual(
            IPv4Address(ipv4status.lan_ipv4_ipaddr), IPv4Address("192.168.1.254")
        )
        self.assertEqual(ipv4status.lan_ipv4_dhcp_enable, True)
        self.assertEqual(
            IPv4Address(ipv4status.lan_ipv4_netmask), IPv4Address("255.255.255.0")
        )

    def test_get_ipv4_reservations(self) -> None:
        client = TplinkWDRRouterTest("", "")
        ipv4_reservations: list[IPv4Reservation] = client.get_ipv4_reservations()
        fRes: IPv4Reservation = ipv4_reservations[0]

        self.assertIsInstance(fRes, IPv4Reservation)
        self.assertEqual(EUI48(fRes.macaddress), EUI48("9B-FA-04-D8-AB-8D"))
        self.assertEqual(IPv4Address(fRes.ipaddress), IPv4Address("192.168.1.56"))
        self.assertEqual(fRes.enabled, True)

    def test_get_ipv4_dhcp_leases(self) -> None:
        client = TplinkWDRRouterTest("", "")
        dhcp_leases: list[IPv4DHCPLease] = client.get_ipv4_dhcp_leases()

        self.assertIsInstance(dhcp_leases[0], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[0].macaddress, EUI48("A9-A8-2B-F7-9F-5D"))
        self.assertEqual(dhcp_leases[0].ipaddress, IPv4Address("192.168.1.123"))
        self.assertEqual(dhcp_leases[0].hostname, "aliquam")
        self.assertEqual(dhcp_leases[0].lease_time, "Permanent")

        self.assertIsInstance(dhcp_leases[1], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[1].macaddress, EUI48("B3-A5-1E-C3-92-A9"))
        self.assertEqual(dhcp_leases[1].ipaddress, IPv4Address("192.168.1.163"))
        self.assertEqual(dhcp_leases[1].hostname, "pharetra")
        self.assertEqual(dhcp_leases[1].lease_time, "Permanent")

    def test_get_status(self) -> None:
        client = TplinkWDRRouterTest("", "")
        client.response = ResponseMock(ABSTRACT_STATUS)

        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, "C4-6E-1F-41-67-C1")
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, "C4-6E-1F-41-67-C0")
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, "192.168.0.129")
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, "192.168.1.254")
        self.assertEqual(status.wan_ipv4_gateway, "192.168.0.1")
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)

        self.assertEqual(status.wired_total, 10)
        self.assertEqual(status.wifi_clients_total, 8)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 18)

        self.assertTrue(status.guest_2g_enable)
        self.assertFalse(status.guest_5g_enable)
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertEqual(status.wan_ipv4_uptime, 6732336)


if __name__ == "__main__":
    main()
