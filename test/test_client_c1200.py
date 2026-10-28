from unittest import main, TestCase
from unittest.mock import Mock, patch
from json import loads
from tplinkrouterc6u import (
    TplinkC1200Router,
    Connection,
    ClientException,
)


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

    def test_set_led_sends_enable_value(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/ledgeneral?form=setting&operation=read":
                    return {"enable": self.state, "ledst_support": "yes"}
                if path == "admin/ledgeneral?form=setting&operation=write":
                    self.writes.append(data)
                    return {}
                raise ClientException()

        client = TPLinkRouterTest("", "")
        client.writes = []

        client.state = "off"
        client.set_led(True)
        client.state = "on"
        client.set_led(False)
        client.set_led(True)

        self.assertEqual(client.writes, ["operation=write&enable=on", "operation=write&enable=off"])

    def test_led_status_method(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/ledgeneral?form=setting&operation=read":
                    return {"enable": "off", "ledst_support": "yes"}
                raise ClientException()

        client = TPLinkRouterTest("", "")

        self.assertFalse(client.led_status())

    def test_get_status_conn_type_is_wan_type(self) -> None:
        response_status = {
            "lan_macaddr": "06-E6-97-9E-23-F5",
            "wan_macaddr": "D6-0B-40-57-DA-60",
            "wan_ipv4_ipaddr": "10.0.0.2",
            "lan_ipv4_ipaddr": "192.168.0.1",
            "wan_ipv4_gateway": "10.0.0.1",
            "conn_type": "0",
            "modem_connstatus": 0,
            "wan_ipv4_conntype": "static",
        }

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/status?form=all&operation=read":
                    return dict(self.status_data)
                return {}

        client = TPLinkRouterTest("", "")
        client.status_data = response_status
        self.assertEqual(client.get_status().conn_type, "static")

        client.status_data = {"lan_macaddr": "06-E6-97-9E-23-F5", "conn_type": "0"}
        self.assertEqual(client.get_status().conn_type, "0")

    def test_get_status_second_5g_band(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/status?form=all&operation=read":
                    return dict(self.status_data)
                return {}

        client = TPLinkRouterTest("", "")
        client.status_data = {
            "lan_macaddr": "06-E6-97-9E-23-F5",
            "wireless_5g_enable": "on",
            "wireless_5g_2_enable": "off",
            "guest_5g_enable": "off",
            "guest_5g_2_enable": "on",
        }
        status = client.get_status()
        self.assertTrue(status.wifi_5g_enable)
        self.assertFalse(status.wifi_5g_2_enable)
        self.assertFalse(status.guest_5g_enable)
        self.assertTrue(status.guest_5g_2_enable)

        client.status_data = {"lan_macaddr": "06-E6-97-9E-23-F5"}
        status = client.get_status()
        self.assertIsNone(status.wifi_5g_2_enable)
        self.assertIsNone(status.guest_5g_2_enable)

    def test_led_night_mode(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/ledpm?form=setting&operation=read":
                    return {"enable": self.state, "time_start": "00:00", "time_end": "23:59", "ledpm_support": "yes"}
                if path == "admin/ledpm?form=setting&operation=write":
                    self.writes.append(data)
                    return {}
                raise ClientException()

        client = TPLinkRouterTest("", "")
        client.writes = []
        client.state = "on"
        self.assertTrue(client.led_night_mode_status())
        client.state = "off"
        self.assertFalse(client.led_night_mode_status())
        client.state = ""
        self.assertIsNone(client.led_night_mode_status())

        client.set_led_night_mode(True)
        client.set_led_night_mode(False)
        self.assertEqual(client.writes, ["operation=write&enable=on", "operation=write&enable=off"])

    @patch('tplinkrouterc6u.client.c6u.post')
    def test_request_sends_form_content_type(self, mock_post) -> None:
        response = Mock()
        response.json.return_value = {'success': True, 'data': {'enable': 'off'}}
        mock_post.return_value = response

        client = TplinkC1200Router('http://192.168.0.1', 'secret')
        client._logged = True
        client._stok = 'stok'
        client._sysauth = 'sysauth'
        client.request('admin/dhcps?form=reservation', 'operation=remove&key=k&index=0')

        headers = mock_post.call_args.kwargs['headers']
        self.assertEqual(headers['Content-Type'], 'application/x-www-form-urlencoded')
        self.assertEqual(headers['Referer'], 'http://192.168.0.1/webpages/index.html')

    @patch('tplinkrouterc6u.client.c6u.post')
    def test_request_sends_parameters_only_once(self, mock_post) -> None:
        response = Mock()
        response.json.return_value = {'success': True, 'data': {'enable': 'off'}}
        mock_post.return_value = response

        client = TplinkC1200Router('http://192.168.0.1', 'secret')
        client._logged = True
        client._stok = 'stok'
        client._sysauth = 'sysauth'

        client.request('admin/ledgeneral?form=setting&operation=read', 'operation=read')
        self.assertEqual(mock_post.call_args.args[0],
                         'http://192.168.0.1/cgi-bin/luci/;stok=stok/admin/ledgeneral?form=setting')
        self.assertEqual(mock_post.call_args.kwargs['data'], 'operation=read')

        client.request('admin/firmware?form=upgrade&operation=read&extra=1', 'operation=read')
        self.assertEqual(mock_post.call_args.args[0],
                         'http://192.168.0.1/cgi-bin/luci/;stok=stok/admin/firmware?form=upgrade&extra=1')

        client.request('admin/ledgeneral?form=setting&operation=read', '')
        self.assertEqual(mock_post.call_args.args[0],
                         'http://192.168.0.1/cgi-bin/luci/;stok=stok/admin/ledgeneral?form=setting&operation=read')

        client.request('admin/vpnconn?form=config&operation=list&vpntype=openvpn', 'operation=list&vpntype=openvpn')
        self.assertEqual(mock_post.call_args.args[0],
                         'http://192.168.0.1/cgi-bin/luci/;stok=stok/admin/vpnconn?form=config')
        self.assertEqual(mock_post.call_args.kwargs['data'], 'operation=list&vpntype=openvpn')

        client.request('admin/wireless?form=guest&form=guest_5g_2', 'operation=write&guest_5g_2_enable=on')
        self.assertEqual(mock_post.call_args.args[0],
                         'http://192.168.0.1/cgi-bin/luci/;stok=stok/admin/wireless?form=guest&form=guest_5g_2')

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
        expected_path = "admin/wireless?form=wireless_5g"

        self.assertEqual(client.captured_path, expected_path)
        self.assertEqual(client.captured_data, expected_data)

    def test_set_wifi_second_5g_band(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.calls.append((path, data))

        client = TPLinkRouterTest("", "")
        client.calls = []
        client.set_wifi(Connection.HOST_5G_2, True)
        client.set_wifi(Connection.GUEST_5G_2, False)

        self.assertEqual(client.calls, [
            ("admin/wireless?form=wireless_5g_2", "operation=write&enable=on"),
            ("admin/wireless?form=guest_5g_2", "operation=write&enable=off"),
        ])

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
                if path == "admin/openvpn?form=config&operation=read":
                    return loads(response_openvpn_read)
                if path == "admin/pptpd?form=config&operation=read":
                    return loads(response_pptp_read)
                if path == "admin/vpnconn?form=config&operation=list&vpntype=openvpn":
                    return loads(respone_vpnconn_openvpn)
                if path == "admin/vpnconn?form=config&operation=list&vpntype=pptp":
                    return loads(respone_vpnconn_pptpvpn)
                raise ClientException()

        client = TPLinkRouterTest("", "")

        vpn_status = client.get_vpn_status()
        self.assertTrue(vpn_status.openvpn_enable)
        self.assertFalse(vpn_status.pptpvpn_enable)
        self.assertEqual(vpn_status.openvpn_clients_total, 2)
        self.assertEqual(vpn_status.pptpvpn_clients_total, 3)


if __name__ == "__main__":
    main()
