from unittest import main, TestCase
from json import loads
from tplinkrouterc6u import (
    TplinkC1200Router,
    Connection,
    ClientException,
)
from tplinkrouterc6u.common.package_enum import VPN


class TestTPLinkC1200Client(TestCase):
    def test_set_led_on(self) -> None:
        response_led_general_read = """
        {
            "enable": "off",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        """

        response_led_general_write = """
        {
            "enable": "on",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        """

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/ledgeneral?form=setting&operation=read":
                    return loads(response_led_general_read)
                if path == "admin/ledgeneral?form=setting&operation=write":
                    self.captured_path = path
                    return loads(response_led_general_write)
                raise ClientException()

        client = TPLinkRouterTest("", "")

        client.set_led(True)

        expected_path = "admin/ledgeneral?form=setting&operation=write"

        self.assertEqual(client.captured_path, expected_path)

    def test_set_led_off(self) -> None:
        response_led_general_read = """
        {
            "enable": "on",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        """

        response_led_general_write = """
        {
            "enable": "off",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        """

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/ledgeneral?form=setting&operation=read":
                    return loads(response_led_general_read)
                if path == "admin/ledgeneral?form=setting&operation=write":
                    self.captured_path = path
                    return loads(response_led_general_write)
                raise ClientException()

        client = TPLinkRouterTest("", "")

        client.set_led(False)

        expected_path = "admin/ledgeneral?form=setting&operation=write"

        self.assertEqual(client.captured_path, expected_path)

    def test_led_status(self) -> None:
        response_led_general_read = """
        {
            "enable": "on",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        """

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/ledgeneral?form=setting&operation=read":
                    return loads(response_led_general_read)
                raise ClientException()

        client = TPLinkRouterTest("", "")

        led_status = client.get_led()
        self.assertTrue(led_status)

    def test_set_wifi(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.captured_path = path
                self.captured_data = data

        client = TPLinkRouterTest("", "")
        client.set_wifi(
            Connection.HOST_5G,
            enable=True,
            ssid="TestSSID",
            hidden="no",
            encryption="WPA3-PSK",
            psk_version="2",
            psk_cipher="AES",
            psk_key="testkey123",
            hwmode="11ac",
            htmode="VHT20",
            channel=36,
            txpower="20",
            disabled_all="no",
        )

        expected_data = (
            "operation=write&enable=on&ssid=TestSSID&hidden=no&encryption=WPA3-PSK&"
            "psk_version=2&psk_cipher=AES&psk_key=testkey123&hwmode=11ac&"
            "htmode=VHT20&channel=36&txpower=20&disabled_all=no"
        )
        expected_path = f"admin/wireless?form=wireless_5g&{expected_data}"

        self.assertEqual(client.captured_path, expected_path)
        self.assertEqual(client.captured_data, expected_data)

    def test_vpn_status(self) -> None:
        response_openvpn_read = """
        {
            "enabled": "on",
            "proto": "udp",
            "access": "home",
            "cert_exist": true,
            "mask": "255.255.255.0",
            "port": "1194",
            "serverip": "10.8.0.0"
        }
        """

        response_pptp_read = """
        {
            "enabled": "off",
            "unencrypted_access": "on",
            "samba_access": "on",
            "netbios_pass": "on",
            "remoteip": "10.0.0.11-20"
        }
        """

        respone_vpnconn_openvpn = """[
            {"username": "admin", "remote_ip": "192.168.0.200", "ipaddr": "10.0.0.11",
             "extra": "7450", "vpntype": "openvpn", "key": "7450"},
            {"username": "admin", "remote_ip": "192.168.0.200", "ipaddr": "10.0.0.11",
             "extra": "7450", "vpntype": "openvpn", "key": "7450"}
        ]"""

        respone_vpnconn_pptpvpn = """[
            {"username": "admin", "remote_ip": "192.168.0.200", "ipaddr": "10.0.0.11",
             "extra": "7450", "vpntype": "pptp", "key": "7450"},
            {"username": "admin", "remote_ip": "192.168.0.200", "ipaddr": "10.0.0.11",
             "extra": "7450", "vpntype": "pptp", "key": "7450"},
            {"username": "admin", "remote_ip": "192.168.0.200", "ipaddr": "10.0.0.11",
             "extra": "7450", "vpntype": "pptp", "key": "7450"}
        ]"""

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "/admin/openvpn?form=config&operation=read":
                    return loads(response_openvpn_read)
                if path == "/admin/pptpd?form=config&operation=read":
                    return loads(response_pptp_read)
                if path == "/admin/vpnconn?form=config&operation=list&vpntype=openvpn":
                    return loads(respone_vpnconn_openvpn)
                if path == "/admin/vpnconn?form=config&operation=list&vpntype=pptp":
                    return loads(respone_vpnconn_pptpvpn)
                raise ClientException()

        client = TPLinkRouterTest("", "")

        vpn_status = client.get_vpn_status()
        self.assertTrue(vpn_status.openvpn_enable)
        self.assertFalse(vpn_status.pptpvpn_enable)
        self.assertEqual(vpn_status.openvpn_clients_total, 2)
        self.assertEqual(vpn_status.pptpvpn_clients_total, 3)

    def test_set_vpn(self) -> None:
        response_openvpn_read = """
        {
            "enabled": "on",
            "proto": "udp",
            "access": "home",
            "cert_exist": true,
            "mask": "255.255.255.0",
            "port": "1194",
            "serverip": "10.8.0.0"
        }
        """

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "/admin/openvpn?form=config&operation=read":
                    return loads(response_openvpn_read)
                self.captured_path = path

        client = TPLinkRouterTest("", "")
        client.set_vpn(VPN.OPEN_VPN, True)

        expected_path = (
            "/admin/openvpn?form=config&operation=write&enabled=on"
            "&proto=udp&access=home&cert_exist=True"
            "&mask=255.255.255.0&port=1194&serverip=10.8.0.0"
        )
        self.assertEqual(client.captured_path, expected_path)


if __name__ == "__main__":
    main()
