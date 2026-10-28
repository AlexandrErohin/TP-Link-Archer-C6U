from datetime import datetime, timezone
from unittest import main, TestCase
from unittest.mock import Mock, patch
from json import loads
from urllib.parse import parse_qsl
from tplinkrouterc6u import (
    TplinkC1200Router,
    Connection,
    ClientError,
    ClientException,
    SecuritySettings,
    HomeCareStatus,
    BlockedThreats,
    IpMacBinding,
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

    def test_get_clients_per_band(self) -> None:
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
                    return dict(self.status_data)
                return {}

        def client_entry(number: int, wire_type: str) -> dict:
            return {"macaddr": "02-00-00-00-00-{:02X}".format(number), "ipaddr": "192.168.0.{}".format(number),
                    "hostname": "client{}".format(number), "wire_type": wire_type}

        client = TPLinkRouterTest("", "")
        client.paths = []
        client.status_data = {
            "lan_macaddr": "06-E6-97-9E-23-F5",
            "wireless_5g_2_enable": "on",
            "access_devices_wired": [client_entry(1, "wired")],
            "access_devices_wireless_host": [client_entry(2, "2.4G"), client_entry(3, "5G"),
                                             client_entry(4, "5G_2"), client_entry(5, "5G_2")],
            "access_devices_wireless_guest": [client_entry(6, "2.4G"), client_entry(7, "5G_2")],
        }

        # No get_status() yet: it reads the status once
        bands = client.get_clients_per_band()
        self.assertEqual((bands.wired, bands.wifi_2g, bands.wifi_5g, bands.wifi_5g_2), (1, 2, 1, 3))
        self.assertEqual(client.paths.count("admin/status?form=all&operation=read"), 1)

        # Afterwards it counts the last get_status() without another request
        client.status_data["access_devices_wireless_host"] = [client_entry(3, "5G")]
        client.get_status()
        client.paths = []
        bands = client.get_clients_per_band()
        self.assertEqual((bands.wired, bands.wifi_2g, bands.wifi_5g, bands.wifi_5g_2), (1, 1, 1, 1))
        self.assertEqual(client.paths, [])

        types = {device.hostname: device.type for device in client.get_status().devices}
        self.assertEqual(types["client3"], Connection.HOST_5G)
        self.assertEqual(types["client6"], Connection.GUEST_2G)
        self.assertEqual(types["client7"], Connection.GUEST_5G_2)

        # Without a second 5 GHz band there is no count for it
        client.status_data = {"lan_macaddr": "06-E6-97-9E-23-F5", "access_devices_wireless_host": [
            client_entry(2, "2.4G"), client_entry(3, "5G")]}
        client.get_status()
        bands = client.get_clients_per_band()
        self.assertEqual((bands.wired, bands.wifi_2g, bands.wifi_5g, bands.wifi_5g_2), (0, 1, 1, None))

    def test_get_daily_traffic(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.calls.append((path, data))
                return self.response

        client = TPLinkRouterTest("", "")
        client.calls = []
        client.response = {
            "day": 3, "hour": 14, "minute": 10, "tick": 23, "max_recent_tick": 7,
            "data": [{"ups": 100 + day, "downs": 1000 + day} for day in range(7)],
        }
        traffic = client.get_daily_traffic()
        self.assertEqual(client.calls, [("admin/traffic?form=data&operation=seg_get",
                                         "operation=seg_get&ip=all&seg_type=day")])
        self.assertEqual(traffic.downloads, [1000, 1001, 1002, 1003, 1004, 1005, 1006])
        self.assertEqual(traffic.uploads, [100, 101, 102, 103, 104, 105, 106])
        self.assertEqual(traffic.download_today, 1000)
        self.assertEqual(traffic.upload_today, 100)

        # Fewer days counted than slots: only those
        client.response = dict(client.response, tick=2)
        self.assertEqual(client.get_daily_traffic().downloads, [1000, 1001])

        # Before the first day is counted the chart shows 0 for today
        client.response = dict(client.response, tick=0)
        traffic = client.get_daily_traffic()
        self.assertEqual((traffic.downloads, traffic.uploads), ([0], [0]))

        # Missing fields: None, never an error
        client.response = {"data": [{"ups": 5}, "x"]}
        traffic = client.get_daily_traffic()
        self.assertEqual(traffic.downloads, [None, None])
        self.assertEqual(traffic.uploads, [5, None])
        self.assertIsNone(traffic.download_today)
        client.response = {}
        traffic = client.get_daily_traffic()
        self.assertEqual((traffic.downloads, traffic.download_today, traffic.upload_today), ([], None, None))

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

    def _wan_client(self, responses: dict) -> TplinkC1200Router:
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
        client.responses = responses
        return client

    def test_get_port_status(self) -> None:
        path = "admin/status?form=router&operation=read"
        rows = [{"wan_status": "connected", "wan_speed": 1000, "wan_duplex": "FULL"},
                {"lan1_duplex": "FULL", "lan1_speed": 1000, "lan1_status": "connected"},
                {"lan2_status": "connected", "lan2_speed": "100", "lan2_duplex": "HALF"},
                {"lan3_speed": "", "lan3_status": "unconnected", "lan3_duplex": ""}]
        rows += [{f"lan{n}_status": "unconnected", f"lan{n}_speed": 0, f"lan{n}_duplex": ""} for n in range(4, 9)]
        ports = self._wan_client({path: rows}).get_port_status()
        self.assertEqual([port.port for port in ports], list(range(9)))
        self.assertEqual((ports[0].link_up, ports[0].negotiated_speed, ports[0].negotiated_duplex),
                         (True, 1000, "full"))
        self.assertEqual((ports[2].link_up, ports[2].negotiated_speed, ports[2].negotiated_duplex),
                         (True, 100, "half"))
        for port in ports[3:]:
            self.assertEqual((port.link_up, port.negotiated_speed, port.negotiated_duplex), (False, None, None))

        ports = self._wan_client({path: [{"wan_status": "disconnected", "wan_speed": 0, "wan_duplex": ""},
                                         {"lan1_status": "new_word"}, {"other": 1}, "junk"]}).get_port_status()
        self.assertEqual([(port.port, port.link_up, port.negotiated_speed) for port in ports],
                         [(0, False, None), (1, None, None)])
        ports = self._wan_client({path: [{"wan_status": "disconnected", "wan_speed": 1000,
                                          "wan_duplex": "FULL"}]}).get_port_status()
        self.assertEqual((ports[0].link_up, ports[0].negotiated_speed), (True, 1000))
        self.assertEqual(self._wan_client({path: []}).get_port_status(), [])
        self.assertEqual(self._wan_client({path: {}}).get_port_status(), [])
        self.assertEqual(self._wan_client({path: None}).get_port_status(), [])

    def test_get_wan_speed(self) -> None:
        path = "admin/status?form=wan_speed&operation=read"
        speed = self._wan_client({path: {"down_speed": 250000, "up_speed": 12000,
                                         "test_time": 1700000000}}).get_wan_speed()
        self.assertEqual(speed.download, 250000)
        self.assertEqual(speed.upload, 12000)
        self.assertEqual(speed.time, datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc))

        speed = self._wan_client({path: {"down_speed": -1, "up_speed": "x"}}).get_wan_speed()
        self.assertEqual((speed.download, speed.upload, speed.time), (None, None, None))
        speed = self._wan_client({path: {}}).get_wan_speed()
        self.assertEqual((speed.download, speed.upload, speed.time), (None, None, None))

    def test_get_speed_test(self) -> None:
        path = "admin/status?form=speedtest&operation=read"
        test = self._wan_client({path: {"status": "idle", "down_speed": 512000, "up_speed": 102400,
                                        "test_time": 1700000000}}).get_speed_test()
        self.assertEqual((test.status, test.download, test.upload), ("idle", 500.0, 100.0))
        self.assertEqual(test.time, datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc))

        test = self._wan_client({path: {"status": "down_test", "down_speed": -1, "up_speed": -1,
                                        "test_time": 1700000000}}).get_speed_test()
        self.assertEqual((test.status, test.download, test.upload), ("down_test", None, None))
        test = self._wan_client({path: {"status": "idle", "down_speed": 0, "up_speed": 0,
                                        "test_time": 0}}).get_speed_test()
        self.assertEqual((test.status, test.download, test.upload, test.time), ("idle", None, None, None))
        test = self._wan_client({path: {}}).get_speed_test()
        self.assertEqual((test.status, test.download, test.upload, test.time), (None, None, None, None))

    def test_start_speed_test(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.calls.append((path, data))
                return {}

        client = TPLinkRouterTest("", "")
        client.calls = []
        client.start_speed_test()
        self.assertEqual(client.calls, [("admin/status?form=speedtest", "operation=start")])

    def test_get_wan_port_speed(self) -> None:
        current = "admin/network?form=port_speed_current&operation=read"
        supported = "admin/network?form=port_speed_supported&operation=read"
        port = self._wan_client({current: {"speed": "1000F"},
                                 supported: {"supported": ["auto", "1000F", "100F"]}}).get_wan_port_speed()
        self.assertEqual((port.value, port.speed, port.duplex, port.auto_negotiation), ("1000F", 1000, "full", False))
        self.assertEqual(port.supported, ["auto", "1000F", "100F"])

        port = self._wan_client({current: {"speed": "auto"}, supported: {}}).get_wan_port_speed()
        self.assertEqual((port.value, port.speed, port.duplex, port.auto_negotiation), ("auto", None, None, True))
        self.assertEqual(port.supported, [])
        port = self._wan_client({current: {"speed": "10H"}, supported: {"supported": "auto"}}).get_wan_port_speed()
        self.assertEqual((port.speed, port.duplex, port.auto_negotiation, port.supported), (10, "half", False, []))
        port = self._wan_client({current: {}, supported: {}}).get_wan_port_speed()
        self.assertEqual((port.value, port.speed, port.duplex, port.auto_negotiation), (None, None, None, None))

    def test_get_qos(self) -> None:
        settings = "admin/qos?form=settings&operation=read"
        dpi = "admin/smart_network?form=dpi_qos&operation=read"
        qos = self._wan_client({
            settings: {"enable_app": "on", "enable": "off", "up_band": "1000", "up_unit": "mbps"},
            dpi: {"upstream_bandwidth": 102400, "downstream_bandwidth": 512000, "qos_mode": "custom",
                  "bandwidth_mode": "auto", "max_download": 1024000, "max_upload": 1024000},
        }).get_qos()
        self.assertEqual((qos.enabled, qos.mode, qos.bandwidth_mode), (False, "custom", "auto"))
        self.assertEqual((qos.download_bandwidth, qos.upload_bandwidth), (500.0, 100.0))

        qos = self._wan_client({settings: {"enable": "on"}, dpi: {}}).get_qos()
        self.assertEqual((qos.enabled, qos.mode, qos.download_bandwidth, qos.upload_bandwidth),
                         (True, None, None, None))
        qos = self._wan_client({settings: {}, dpi: {}}).get_qos()
        self.assertIsNone(qos.enabled)

    def test_get_security_settings(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.paths.append(path)
                if path not in self.responses:
                    raise ClientError("no such callback")
                return self.responses[path]

        client = TPLinkRouterTest("", "")
        client.paths = []
        client.responses = {
            "admin/administration?form=remote&operation=read": {
                "web_address": "https://203.0.113.5:443", "http_port": "80", "enable": "off",
                "https_port": "443", "remote": False, "managers": "all"},
            "admin/administration?form=https&operation=read": {"https_enable": "off"},
            "admin/nat?form=dmz&operation=read": {"enable": "on", "ipaddr": "192.168.0.10"},
            "admin/nat?form=vs&operation=read": [
                {"enable": "on", "external_port": "8080", "internal_port": "80", "ipaddr": "192.168.0.10",
                 "name": "web", "protocol": "ALL"},
                {"enable": "off", "external_port": "22", "internal_port": "22", "ipaddr": "192.168.0.11",
                 "name": "ssh", "protocol": "TCP"},
            ],
            "admin/upnp?form=enable&operation=read": {"enable": "on"},
            "admin/upnp?form=service&operation=read": [
                {"external_port": "50000", "internal_port": "50000", "ipaddr": "192.168.0.10",
                 "leasetime": "02:00:00", "name": "Console", "protocol": "UDP"},
                {"external_port": "50001", "internal_port": "50001", "ipaddr": "192.168.0.10",
                 "leasetime": "02:00:00", "name": "Console", "protocol": "UDP"},
                {"external_port": "6000", "internal_port": "6000", "ipaddr": "192.168.0.11",
                 "leasetime": "00:30:00", "name": "Game", "protocol": "tcp"},
            ],
            "admin/security_settings?form=new_enable&operation=read": {
                "enable": "off", "lan_ping": "on", "wan_ping": "off"},
            "admin/access_control?form=enable&operation=read": {"enable": "on", "host_mac": "06-E6-97-9E-23-F5"},
            "admin/access_control?form=mode&operation=read": {"access_mode": "black"},
            "admin/access_control?form=black_list&operation=load": {},
        }
        settings = client.get_security_settings()
        self.assertIsInstance(settings, SecuritySettings)
        self.assertFalse(settings.remote_management)
        self.assertTrue(settings.remote_management_any_address)
        self.assertEqual(settings.remote_management_http_port, 80)
        self.assertEqual(settings.remote_management_https_port, 443)
        self.assertFalse(settings.local_https)
        self.assertTrue(settings.dmz)
        self.assertEqual(settings.dmz_host, "192.168.0.10")
        self.assertTrue(settings.upnp)
        self.assertEqual(settings.upnp_mappings, 3)
        self.assertEqual(settings.upnp_mappings_by_protocol, {"UDP": 2, "TCP": 1})
        self.assertEqual(settings.port_forwards, 2)
        self.assertEqual(settings.port_forwards_enabled, 1)
        self.assertFalse(settings.spi_firewall)
        self.assertFalse(settings.ping_from_wan)
        self.assertTrue(settings.ping_from_lan)
        self.assertTrue(settings.access_control)
        self.assertEqual(settings.access_control_mode, "blacklist")
        self.assertEqual(settings.access_control_blocked, 0)
        # Never the WAN address or the admin's MAC
        self.assertNotIn("203.0.113.5", str(settings))
        self.assertNotIn("06-E6-97-9E-23-F5", str(settings))

        # DMZ off: no host; whitelist mode: the block list is not read
        client.responses["admin/nat?form=dmz&operation=read"] = {"enable": "off", "ipaddr": "192.168.0.10"}
        client.responses["admin/access_control?form=mode&operation=read"] = {"access_mode": "white"}
        client.paths = []
        settings = client.get_security_settings()
        self.assertFalse(settings.dmz)
        self.assertIsNone(settings.dmz_host)
        self.assertEqual(settings.access_control_mode, "whitelist")
        self.assertIsNone(settings.access_control_blocked)
        self.assertNotIn("admin/access_control?form=black_list&operation=load", client.paths)

        # Pages the firmware lacks or empty answers: None, never an error
        client.responses = {"admin/nat?form=dmz&operation=read": {},
                            "admin/upnp?form=service&operation=read": []}
        settings = client.get_security_settings()
        self.assertIsNone(settings.remote_management)
        self.assertIsNone(settings.remote_management_any_address)
        self.assertIsNone(settings.dmz)
        self.assertIsNone(settings.upnp)
        self.assertEqual(settings.upnp_mappings, 0)
        self.assertEqual(settings.upnp_mappings_by_protocol, {})
        self.assertIsNone(settings.port_forwards)
        self.assertIsNone(settings.spi_firewall)
        self.assertIsNone(settings.access_control)
        self.assertIsNone(settings.access_control_mode)
        self.assertIsNone(settings.access_control_blocked)

    def test_get_homecare_status(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path not in self.responses:
                    raise ClientError("no such callback")
                return self.responses[path]

        client = TPLinkRouterTest("", "")
        client.responses = {
            "admin/security?form=info&operation=read": {
                "is_updating": False, "intrusion_prevention_system": "enable", "malicious_sites_blocking": "enable",
                "checked_time": 1792694581, "protected_days": 143, "infected_device_prevention_blocking": "disable"},
            "admin/security?form=rule&operation=read": {"version": 1216, "rule_list": [{"id": 1, "name": "Rule"}]},
        }
        status = client.get_homecare_status()
        self.assertIsInstance(status, HomeCareStatus)
        self.assertTrue(status.malicious_content_filter)
        self.assertTrue(status.intrusion_prevention)
        self.assertFalse(status.infected_device_quarantine)
        self.assertEqual(status.protected_days, 143)
        self.assertEqual(status.database_checked, datetime(2026, 10, 22, 18, 43, 1, tzinfo=timezone.utc))
        self.assertFalse(status.database_updating)
        self.assertEqual(status.rules_version, 1216)

        client.responses = {"admin/security?form=info&operation=read": {}}
        status = client.get_homecare_status()
        self.assertIsNone(status.malicious_content_filter)
        self.assertIsNone(status.protected_days)
        self.assertIsNone(status.database_checked)
        self.assertIsNone(status.database_updating)
        self.assertIsNone(status.rules_version)

    def test_get_blocked_threats(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.paths.append(path)
                return self.response

        client = TPLinkRouterTest("", "")
        client.paths = []
        client.response = [
            {"attacker": "", "blocked_website": "bad.example.com", "category_id": 4, "client": "Laptop",
             "event_id": 1, "hits": 3, "owner": "Alice", "rule_id": 0, "timestamp": 1792694581, "type": "block"},
            {"attacker": "198.51.100.7", "blocked_website": "", "category_id": 0, "client": "Laptop",
             "event_id": 2, "hits": 1, "owner": "Alice", "rule_id": 1050694, "timestamp": 1792780981,
             "type": "prevent"},
            {"attacker": "", "blocked_website": "worse.example.com", "category_id": "2", "client": "Phone",
             "event_id": 3, "hits": "2", "owner": "Bob", "rule_id": 0, "timestamp": "1792700000", "type": "block"},
        ]
        threats = client.get_blocked_threats()
        self.assertEqual(client.paths, ["admin/security?form=history&operation=read"])
        self.assertIsInstance(threats, BlockedThreats)
        self.assertEqual(threats.events, 3)
        self.assertEqual(threats.hits, 6)
        self.assertEqual(threats.by_type, {"block": 2, "prevent": 1})
        self.assertEqual(threats.last_time, datetime(2026, 10, 23, 18, 43, 1, tzinfo=timezone.utc))
        self.assertEqual(threats.last_type, "prevent")
        self.assertEqual(threats.last_category_id, 0)
        for personal in ("bad.example.com", "198.51.100.7", "Laptop", "Alice", "Phone", "Bob"):
            self.assertNotIn(personal, str(threats))

        for empty in ([], {}, None):
            client.response = empty
            threats = client.get_blocked_threats()
            self.assertEqual(threats.events, 0)
            self.assertEqual(threats.hits, 0)
            self.assertEqual(threats.by_type, {})
            self.assertIsNone(threats.last_time)
            self.assertIsNone(threats.last_type)
            self.assertIsNone(threats.last_category_id)

    def test_get_ip_mac_binding(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path not in self.responses:
                    raise ClientError("no such callback")
                return self.responses[path]

        client = TPLinkRouterTest("", "")
        client.responses = {
            "admin/imb?form=setting&operation=read": {"enable": "on"},
            "admin/imb?form=arp_list&operation=load": [
                {"mac": "06-E6-97-9E-23-F5", "ipaddr": "192.168.0.10", "enable": "off"},
                {"mac": "06-E6-97-9E-23-F6", "ipaddr": "192.168.0.11", "enable": "on"},
            ],
            "admin/imb?form=bind_list&operation=load": [],
        }
        binding = client.get_ip_mac_binding()
        self.assertIsInstance(binding, IpMacBinding)
        self.assertTrue(binding.enable)
        self.assertEqual(binding.arp_entries, 2)
        self.assertEqual(binding.bindings, 0)

        client.responses = {}
        binding = client.get_ip_mac_binding()
        self.assertIsNone(binding.enable)
        self.assertIsNone(binding.arp_entries)
        self.assertIsNone(binding.bindings)

    def test_get_firmware_update(self) -> None:
        installed = "1.2.1 Build 20250928 rel.12879(5553)"
        newer = "1.2.2 Build 20260301 rel.13000(5553)"

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.calls.append((path, data))
                response = self.responses.get(path)
                if response is None:
                    raise ClientError("no such callback")
                return response

        client = TPLinkRouterTest("", "")
        client.calls = []
        client.responses = {
            "admin/firmware?form=upgrade&operation=read": {"hardware_version": "ArcherC5400X v1.0",
                                                           "model": "ArcherC5400X", "totaltime": 45,
                                                           "is_default": False, "firmware_version": installed},
            "admin/cloud_account?form=check_upgrade&operation=read": {"update_number": 1},
            "admin/cloud_account?form=cloud_upgrade&operation=load": {
                "latest_version": newer, "detail": "Modifications:\\n1. Fixes.\\tMore", "latest_flag": False,
                "note_flag": False},
        }
        update = client.get_firmware_update()
        self.assertEqual(update.installed_version, installed)
        self.assertEqual(update.latest_version, newer)
        self.assertTrue(update.update_available)
        self.assertEqual(update.release_notes, "Modifications:\n1. Fixes.\tMore")
        # Read only: never the upgrade operation
        self.assertEqual([data for _, data in client.calls], ["operation=read", "operation=read", "operation=load"])

        client.responses["admin/cloud_account?form=check_upgrade&operation=read"] = {"update_number": 0}
        client.responses["admin/cloud_account?form=cloud_upgrade&operation=load"] = {
            "latest_version": installed, "detail": "", "latest_flag": True, "note_flag": False}
        update = client.get_firmware_update()
        self.assertFalse(update.update_available)
        self.assertEqual(update.latest_version, installed)
        self.assertIsNone(update.release_notes)

        # No answer from the cloud: the installed version is still known
        del client.responses["admin/cloud_account?form=check_upgrade&operation=read"]
        del client.responses["admin/cloud_account?form=cloud_upgrade&operation=load"]
        update = client.get_firmware_update()
        self.assertEqual(update.installed_version, installed)
        self.assertIsNone(update.latest_version)
        self.assertIsNone(update.update_available)

        client.responses = {"admin/firmware?form=upgrade&operation=read": {},
                            "admin/cloud_account?form=check_upgrade&operation=read": {},
                            "admin/cloud_account?form=cloud_upgrade&operation=load": {}}
        update = client.get_firmware_update()
        self.assertIsNone(update.installed_version)
        self.assertIsNone(update.update_available)

    def test_reboot_schedule(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/reboot?form=set&operation=read":
                    return self.response
                self.writes.append((path, data))
                return {}

        client = TPLinkRouterTest("", "")
        client.writes = []
        client.response = {"enable": "off", "cycle": "week", "time": "03:00", "day": "Mon"}
        schedule = client.get_reboot_schedule()
        self.assertFalse(schedule.enable)
        self.assertEqual((schedule.time, schedule.cycle, schedule.day), ("03:00", "week", "Mon"))

        client.set_reboot_schedule(True)
        path, data = client.writes[0]
        self.assertEqual(path, "admin/reboot?form=set")
        self.assertEqual(dict(parse_qsl(data)),
                         {"operation": "write", "enable": "on", "time": "03:00", "cycle": "week", "day": "Mon"})

        client.writes = []
        client.set_reboot_schedule(False, time="04:30", cycle="day")
        self.assertEqual(dict(parse_qsl(client.writes[0][1])),
                         {"operation": "write", "enable": "off", "time": "04:30", "cycle": "day", "day": "Mon"})

        client.response = {}
        schedule = client.get_reboot_schedule()
        self.assertIsNone(schedule.enable)
        self.assertIsNone(schedule.time)

    def test_get_router_time(self) -> None:
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
            "admin/time?form=settings&operation=read": {
                "hour24_support": "yes", "type": "auto", "hour24_enable": "on", "ntp_svr2": "time-nw.nist.gov",
                "date": "10/28/2026", "ntp_svr1": "time.nist.gov", "timezone": "20", "time": "15:02:05",
                "time_format": "UN_FORMAT", "quicksetup": "no", "day": "Wed"},
            "admin/time?form=dst&operation=read": {
                "end_month": "Nov", "start_hour": "2am", "end_week": "1st", "date": "10/28/2026",
                "start_month": "Mar", "end_hour": "2am", "time": "15:02:05", "start_day": "Sun",
                "dst_status": "up", "dst_enable": "on", "start_week": "2nd", "end_day": "Sun"},
        }
        router_time = client.get_router_time()
        self.assertEqual(router_time.time, datetime(2026, 10, 28, 15, 2, 5))
        self.assertIsNotNone(router_time.read_at.tzinfo)
        self.assertTrue(router_time.automatic)
        self.assertEqual(router_time.timezone, "20")
        self.assertEqual(router_time.ntp_servers, ["time.nist.gov", "time-nw.nist.gov"])
        self.assertTrue(router_time.dst_enable)
        self.assertTrue(router_time.dst_active)
        self.assertEqual(router_time.dst_start, "2nd Sun Mar 2am")
        self.assertEqual(router_time.dst_end, "1st Sun Nov 2am")

        client.responses["admin/time?form=settings&operation=read"] = {
            "date": "28/10/2026", "time": "15:02:05", "time_format": "BR_FORMAT", "type": "manual"}
        router_time = client.get_router_time()
        self.assertEqual(router_time.time, datetime(2026, 10, 28, 15, 2, 5))
        self.assertFalse(router_time.automatic)

        client.responses = {path: {} for path in client.responses}
        router_time = client.get_router_time()
        self.assertIsNone(router_time.time)
        self.assertIsNone(router_time.read_at)
        self.assertIsNone(router_time.automatic)
        self.assertEqual(router_time.ntp_servers, [])
        self.assertIsNone(router_time.dst_active)
        self.assertIsNone(router_time.dst_start)

    def test_get_system_log(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.calls.append((path, data))
                return self.response

        client = TPLinkRouterTest("", "")
        client.calls = []
        client.response = [
            {"time": "2026-10-28 15:00:01", "type": "DHCPD", "level": "INFO", "content": "DHCPS: ..."},
            {"time": "2026-10-28 15:00:02", "type": "DHCPD", "level": "INFO", "content": "DHCPS: ..."},
            {"time": "2026-10-28 15:00:03", "type": "WIRELESS", "level": "WARNING", "content": "..."},
            {"time": "2026-10-28 15:00:04", "type": "NAT", "content": "..."},
        ]
        log = client.get_system_log()
        self.assertEqual(client.calls, [("admin/syslog?form=log&operation=load", "operation=load")])
        self.assertEqual(log.entries, 4)
        self.assertEqual(log.levels, {"info": 2, "warning": 1, "unknown": 1})

        client.response = []
        self.assertEqual(client.get_system_log().entries, 0)
        client.response = {}
        log = client.get_system_log()
        self.assertIsNone(log.entries)
        self.assertEqual(log.levels, {})

    def test_traffic_monitor(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.calls.append((path, data))
                return self.response

        client = TPLinkRouterTest("", "")
        client.calls = []
        client.response = {"enable": "off"}
        self.assertFalse(client.traffic_monitor_status())
        client.response = {"enable": "on"}
        self.assertTrue(client.traffic_monitor_status())
        client.response = {}
        self.assertIsNone(client.traffic_monitor_status())

        client.calls = []
        client.set_traffic_monitor(True)
        client.set_traffic_monitor(False)
        self.assertEqual(client.calls, [("admin/traffic?form=status", "operation=write&enable=on"),
                                        ("admin/traffic?form=status", "operation=write&enable=off")])

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

    def test_get_wifi_networks(self) -> None:
        main_5g = {
            "disabled": "off", "disabled_all": "off", "current_channel": "48", "disabled_by": "0", "hidden": "off",
            "macaddr": "06-E6-97-9E-23-F5", "encryption": "psk", "enable": "on", "hwmode": "anac_5", "htmode": "auto",
            "wps_state": "configured", "wpa_key": "", "ssid": "MyNetwork-5G", "txpower": "high",
            "psk_key": "secret&key", "wep_key1": "", "channel": "auto", "airtime_fairness": "on", "mu_mimo": "on",
        }
        guest = {"ssid": "MyGuest", "disabled_by": "0", "enable": "off", "hidden": "off", "disabled": "off",
                 "encryption": "none", "psk_key": "secret"}

        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                self.paths.append(path)
                form = path.split("form=", 1)[1].split("&", 1)[0]
                if form in self.responses:
                    return self.responses[form]
                raise ClientException("no such form")

        client = TPLinkRouterTest("", "")
        client.paths = []
        client.responses = {
            "wireless_2g": {"enable": "on", "ssid": "MyNetwork", "channel": "6", "current_channel": "6",
                            "hwmode": "bgn", "mu_mimo": "off"},
            "wireless_5g": main_5g,
            "guest_2g": guest,
            "guest_5g": {"wireless": "unknown"},
        }
        networks = client.get_wifi_networks()

        self.assertEqual(client.paths[0], "admin/wireless?form=wireless_2g&operation=read")
        self.assertEqual(len(client.paths), 6)
        # wireless_5g_2 and guest_5g_2 fail (dual-band): left out
        self.assertEqual(list(networks), ["wireless_2g", "wireless_5g", "guest_2g", "guest_5g"])
        five = networks["wireless_5g"]
        self.assertTrue(five.enable)
        self.assertEqual(five.ssid, "MyNetwork-5G")
        self.assertFalse(five.hidden)
        self.assertEqual(five.encryption, "psk")
        self.assertEqual(five.channel, "auto")
        self.assertEqual(five.current_channel, 48)
        self.assertEqual((five.hwmode, five.htmode, five.txpower), ("anac_5", "auto", "high"))
        self.assertTrue(five.airtime_fairness)
        self.assertTrue(five.mu_mimo)
        for network in networks.values():
            self.assertNotIn("secret", str(network))
            self.assertFalse(hasattr(network, "psk_key"))
        self.assertEqual(networks["wireless_2g"].channel, "6")
        self.assertIsNone(networks["wireless_2g"].txpower)
        self.assertFalse(networks["wireless_2g"].mu_mimo)
        self.assertEqual((networks["guest_2g"].ssid, networks["guest_2g"].enable), ("MyGuest", False))
        self.assertEqual(networks["guest_2g"].encryption, "none")
        self.assertIsNone(networks["guest_2g"].current_channel)
        self.assertIsNone(networks["guest_2g"].mu_mimo)
        self.assertIsNone(networks["guest_5g"].ssid)
        self.assertIsNone(networks["guest_5g"].enable)

        # Prefixed keys (multi-form answer) are read too
        client.responses = {"wireless_5g_2": {"wireless_5g_2_ssid": "MyNetwork", "wireless_5g_2_enable": "off",
                                              "wireless_5g_2_current_channel": "149"}}
        networks = client.get_wifi_networks()
        self.assertEqual(list(networks), ["wireless_5g_2"])
        self.assertEqual((networks["wireless_5g_2"].ssid, networks["wireless_5g_2"].enable), ("MyNetwork", False))
        self.assertEqual(networks["wireless_5g_2"].current_channel, 149)

        # Nothing could be read: the error goes up
        client.responses = {}
        with self.assertRaises(ClientException):
            client.get_wifi_networks()

    def test_wifi_schedule(self) -> None:
        class TPLinkRouterTest(TplinkC1200Router):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if data.startswith("operation=write"):
                    self.writes.append((path, data))
                    return {}
                if path == "admin/wireless?form=wireless_schedule&operation=read":
                    return self.schedule
                if path == "admin/wireless?form=wireless_schedule_wifi_disable&operation=read":
                    if self.now is None:
                        raise ClientException("no such callback")
                    return self.now
                raise ClientException()

        client = TPLinkRouterTest("", "")
        client.writes = []
        client.schedule = {"enable": "off", "list": {}}
        client.now = {"disable_52g": False, "disable_2g": False, "disable_5g": False}
        schedule = client.wifi_schedule_status()
        self.assertFalse(schedule.enable)
        self.assertEqual(schedule.off_periods, 0)
        self.assertEqual((schedule.off_now_2g, schedule.off_now_5g, schedule.off_now_5g_2), (False, False, False))

        client.schedule = {"enable": "on", "list": ["eve:[0,6]", "1,2:[22,24]"]}
        client.now = {"disable_2g": True, "disable_5g": "off"}
        schedule = client.wifi_schedule_status()
        self.assertTrue(schedule.enable)
        self.assertEqual(schedule.off_periods, 2)
        self.assertEqual((schedule.off_now_2g, schedule.off_now_5g, schedule.off_now_5g_2), (True, False, None))

        client.schedule = {}
        client.now = None
        schedule = client.wifi_schedule_status()
        self.assertIsNone(schedule.enable)
        self.assertIsNone(schedule.off_periods)
        self.assertIsNone(schedule.off_now_2g)

        client.set_wifi_schedule(True)
        client.set_wifi_schedule(False)
        self.assertEqual(client.writes, [
            ("admin/wireless?form=wireless_schedule", "operation=write&enable=on"),
            ("admin/wireless?form=wireless_schedule", "operation=write&enable=off"),
        ])

    def test_wps_and_guest_network_access(self) -> None:
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
            "admin/wireless?form=syspara_wps&operation=read": {"wps": "off"},
            "admin/wireless?form=guest&operation=read": {"isolate": "on", "access": "off"},
        }
        self.assertFalse(client.wps_status())
        access = client.guest_network_access()
        self.assertTrue(access.each_other)
        self.assertFalse(access.local_network)

        client.responses = {
            "admin/wireless?form=syspara_wps&operation=read": {"wps": "on"},
            "admin/wireless?form=guest&operation=read": {"access": "on"},
        }
        self.assertTrue(client.wps_status())
        access = client.guest_network_access()
        self.assertIsNone(access.each_other)
        self.assertTrue(access.local_network)

        client.responses = {
            "admin/wireless?form=syspara_wps&operation=read": {},
            "admin/wireless?form=guest&operation=read": {},
        }
        self.assertIsNone(client.wps_status())
        self.assertEqual((client.guest_network_access().each_other, client.guest_network_access().local_network),
                         (None, None))

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
