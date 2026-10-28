from unittest import main, TestCase
from unittest.mock import Mock, patch
from json import loads
from urllib.parse import parse_qsl
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

    def test_get_status_client_traffic(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.paths.append(path)
                if path == "admin/status?form=all&operation=read":
                    return {
                        "lan_macaddr": "06-E6-97-9E-23-F5",
                        "access_devices_wired": [
                            {"macaddr": "02-00-00-00-00-01", "ipaddr": "192.168.0.10", "hostname": "pc",
                             "wire_type": "wired"},
                        ],
                        "access_devices_wireless_host": [
                            {"macaddr": "02-00-00-00-00-02", "ipaddr": "192.168.0.11", "hostname": "phone",
                             "wire_type": "5G"},
                        ],
                    }
                if path == "admin/traffic?form=lists&operation=load":
                    if self.traffic is None:
                        raise ClientException("no such callback")
                    return self.traffic
                return {}

        client = TPLinkRouterTest("", "")
        client.paths = []
        client.traffic = [
            {"mac": "02-00-00-00-00-01", "ip": "192.168.0.10", "total_byte": 1000, "retx_byte": 10,
             "rerx_byte": 200},
            {"mac": "02-00-00-00-00-01", "ip": "192.168.0.99", "total_byte": 500, "retx_byte": 0, "rerx_byte": 0},
            {"mac": "02-00-00-00-00-09", "ip": "192.168.0.12", "total_byte": 7, "retx_byte": 1, "rerx_byte": 1},
        ]
        status = client.get_status()
        self.assertEqual(status.clients_down_speed, 201)
        self.assertEqual(status.clients_up_speed, 11)
        devices = {device.hostname: device for device in status.devices}
        self.assertEqual(devices["pc"].down_speed, 200)
        self.assertEqual(devices["pc"].up_speed, 10)
        self.assertEqual(devices["pc"].traffic_usage, 1500)
        self.assertIsNone(devices["phone"].down_speed)
        self.assertIsNone(devices["phone"].traffic_usage)

        client.traffic = None
        client._traffic_lists = True
        status = client.get_status()
        self.assertIsNone(status.devices[0].down_speed)
        self.assertIsNone(status.clients_down_speed)
        client.paths = []
        client.get_status()
        self.assertNotIn("admin/traffic?form=lists&operation=load", client.paths)

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

    def test_get_port_modes(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                return self.responses[path]

        client = TPLinkRouterTest("", "")
        client.responses = {
            "admin/network?form=addl_wan&operation=read": {"addl_wan_port": "1", "addl_wan_enable": "0"},
            "admin/network?form=lan_agg&operation=read": {"lacpmode": "2", "LAN2": "1", "LAN3": "1",
                                                          "enable_agg": "1"},
            "admin/iptv?form=setting&operation=read": {"enable": "off", "mode": "Bridge", "lan7": "IPTV"},
        }
        modes = client.get_port_modes()
        self.assertFalse(modes.wan_aggregation)
        self.assertTrue(modes.link_aggregation)
        self.assertFalse(modes.iptv)

        client.responses = {path: {} for path in client.responses}
        modes = client.get_port_modes()
        self.assertIsNone(modes.wan_aggregation)
        self.assertIsNone(modes.link_aggregation)
        self.assertIsNone(modes.iptv)

    def test_nat_boost_status(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                return self.response

        client = TPLinkRouterTest("", "")
        client.response = {"hw_enable": "off", "boost_support": "yes", "enable": "on",
                           "boost_traffic_compatible": "yes", "boost_qos_compatible": "no", "reboot_time": 45}
        self.assertFalse(client.nat_boost_status())
        client.response = dict(client.response, hw_enable="on")
        self.assertTrue(client.nat_boost_status())
        client.response = {"enable": "on"}
        self.assertIsNone(client.nat_boost_status())

    def test_smart_connect(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/wireless?form=smart_connect&operation=read":
                    return {"smart_enable": self.state}
                if path == "admin/wireless?form=wireless_2g":
                    return {
                        "wireless_2g_enable": "on",
                        "wireless_2g_ssid": "Home",
                        "wireless_2g_hidden": "off",
                        "wireless_2g_encryption": "psk",
                        "wireless_2g_psk_version": "rsn",
                        "wireless_2g_psk_cipher": "auto",
                        "wireless_2g_psk_key": "secret&key",
                        "wireless_2g_disabled_all": "off",
                        "wireless_2g_channel": "auto",
                    }
                self.writes.append((path, data))
                return {}

        client = TPLinkRouterTest("", "")
        client.writes = []
        client.state = "on"
        self.assertTrue(client.smart_connect_status())
        client.state = "off"
        self.assertFalse(client.smart_connect_status())
        client.state = ""
        self.assertIsNone(client.smart_connect_status())

        client.set_smart_connect(False)
        self.assertEqual(client.writes, [("admin/wireless?form=smart_connect", "operation=write&smart_enable=off")])

        client.writes = []
        client.set_smart_connect(True)
        self.assertEqual(client.writes[0], ("admin/wireless?form=smart_connect", "operation=write&smart_enable=on"))
        path, data = client.writes[1]
        self.assertEqual(path, "admin/wireless?form=wireless_5g&form=wireless_5g_2")
        sent = dict(parse_qsl(data))
        self.assertEqual(sent.pop("operation"), "write")
        for band in ("wireless_5g", "wireless_5g_2"):
            self.assertEqual(sent.pop(band + "_ssid"), "Home")
            self.assertEqual(sent.pop(band + "_psk_key"), "secret&key")
            for key, value in (("enable", "on"), ("hidden", "off"), ("encryption", "psk"),
                               ("psk_version", "rsn"), ("psk_cipher", "auto"), ("disabled_all", "off")):
                self.assertEqual(sent.pop("{}_{}".format(band, key)), value)
        self.assertEqual(sent, {})

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

    def test_get_usb_storage(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.paths.append((path, data))
                if path not in self.responses:
                    raise ClientException()
                return self.responses[path]

        client = TPLinkRouterTest("", "")
        client.paths = []
        client.responses = {"admin/disk_setting?form=metadata&operation=read": {"number": 0, "list": {}}}
        storage = client.get_usb_storage()
        self.assertEqual(storage.disks, 0)
        self.assertIsNone(storage.capacity)
        self.assertIsNone(storage.used)
        self.assertIsNone(storage.free)
        self.assertEqual(client.paths, [("admin/disk_setting?form=metadata&operation=read", "operation=read")])

        client.responses = {
            "admin/disk_setting?form=metadata&operation=read": {
                "number": 2, "list": [{"serial": "AB 12", "name": "Disk"}, {"serial": "CD34", "name": "Disk"}]},
            "admin/disk_setting?form=contents&serial=AB%2012&operation=load": [
                {"volumn": "Volume1", "capacity": "16GB", "enable": "on", "free": "10GB", "uuid": "0001"},
                {"volumn": "Volume2", "capacity": "1.5T", "used": "0.5T", "free": "1T", "uuid": "0002"},
                {"volumn": "Volume3", "capacity": "---", "free": "", "uuid": "0003"},
            ],
        }
        storage = client.get_usb_storage()
        self.assertEqual(storage.disks, 2)
        self.assertEqual(storage.capacity, 16 * 10 ** 9 + 15 * 10 ** 11)
        self.assertEqual(storage.used, 6 * 10 ** 9 + 5 * 10 ** 11)
        self.assertEqual(storage.free, 10 * 10 ** 9 + 10 ** 12)

        client.responses = {"admin/disk_setting?form=metadata&operation=read": {}}
        storage = client.get_usb_storage()
        self.assertIsNone(storage.disks)
        self.assertIsNone(storage.capacity)

    def test_get_usb_sharing(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                return self.responses[path]

        client = TPLinkRouterTest("", "")
        client.responses = {
            "admin/folder_sharing?form=settings&operation=read": [
                {"port": "---", "key": 1, "edit": False, "enable": "on", "protocol": "samba", "link": "\\MyShare"},
                {"port": 21, "key": 2, "edit": False, "enable": "off", "protocol": "ftp",
                 "link": "ftp://192.168.0.1:21"},
                {"port": "21", "key": 3, "edit": True, "enable": "on", "protocol": "ftpex", "link": "ftp://0.0.0.0:21"},
            ],
            "admin/folder_sharing?form=media&operation=read": {"media_sharing": "off"},
            "admin/time_machine?form=settings&operation=read": {
                "mntdir": "", "disk_status": "1", "enable": "on", "free": 0, "capacity": 0, "limitsize": "0"},
        }
        sharing = client.get_usb_sharing()
        self.assertTrue(sharing.samba)
        self.assertFalse(sharing.ftp)
        self.assertTrue(sharing.ftp_internet)
        self.assertFalse(sharing.media_sharing)
        self.assertTrue(sharing.time_machine)

        client.responses = {path: {} for path in client.responses}
        sharing = client.get_usb_sharing()
        self.assertIsNone(sharing.samba)
        self.assertIsNone(sharing.ftp)
        self.assertIsNone(sharing.ftp_internet)
        self.assertIsNone(sharing.media_sharing)
        self.assertIsNone(sharing.time_machine)

    def test_print_server_status(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.sent = (path, data)
                return self.response

        client = TPLinkRouterTest("", "")
        client.response = {"enable": "on", "name": "\\MyPrinter", "printer_count": 1}
        self.assertTrue(client.print_server_status())
        self.assertEqual(client.sent, ("admin/print_server", "operation=read"))
        client.response = {"enable": "off"}
        self.assertFalse(client.print_server_status())
        client.response = {}
        self.assertIsNone(client.print_server_status())

    def test_get_vpn_server_settings(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                return self.responses[path]

        client = TPLinkRouterTest("", "")
        client.responses = {
            "admin/openvpn?form=config&operation=read": {
                "enabled": "on", "proto": "udp", "access": "home", "cert_exist": True, "mask": "255.255.255.0",
                "port": "1194", "serverip": "10.8.0.0"},
            "admin/pptpd?form=config&operation=read": {
                "enabled": "off", "unencrypted_access": "on", "samba_access": "off", "netbios_pass": "on",
                "remoteip": "10.0.0.11-20"},
        }
        settings = client.get_vpn_server_settings()
        self.assertTrue(settings.openvpn_enabled)
        self.assertEqual(settings.openvpn_protocol, "udp")
        self.assertEqual(settings.openvpn_port, 1194)
        self.assertEqual(settings.openvpn_access, "home")
        self.assertFalse(settings.pptp_enabled)
        self.assertTrue(settings.pptp_unencrypted_access)
        self.assertFalse(settings.pptp_samba_access)
        self.assertFalse(hasattr(settings, "netbios_pass"))
        self.assertFalse(hasattr(settings, "cert_exist"))

        client.responses = {path: {} for path in client.responses}
        settings = client.get_vpn_server_settings()
        self.assertIsNone(settings.openvpn_enabled)
        self.assertIsNone(settings.openvpn_protocol)
        self.assertIsNone(settings.openvpn_port)
        self.assertIsNone(settings.openvpn_access)
        self.assertIsNone(settings.pptp_enabled)
        self.assertIsNone(settings.pptp_unencrypted_access)
        self.assertIsNone(settings.pptp_samba_access)


if __name__ == "__main__":
    main()
