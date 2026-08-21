from unittest import TestCase, main
from unittest.mock import Mock

from tplinkrouterc6u import PortStatus, TPLinkSG108EClient
from tplinkrouterc6u.client.sg108e import parse_script_variables


class TestSG108EParser(TestCase):
    def test_parse_script_variables_with_attributes(self) -> None:
        html = """<html><head>
        <script type=\"text/javascript\">var g_title = 'TL-SG108E'; var led = 1;</script>
        </head></html>"""
        vars = parse_script_variables(html)
        self.assertEqual(vars.get('g_title'), 'TL-SG108E')
        self.assertEqual(vars.get('led'), 1)

    def test_parse_multiline_object_literal_like_live_device(self) -> None:
        html = """<html><script>
        var info_ds = {
          descriStr:[ \"TL-SG108E\" ],
          macStr:[ \"02:00:00:00:00:01\" ],
          ipStr:[ \"192.0.2.23\" ],
          netmaskStr:[ \"255.255.255.0\" ],
          gatewayStr:[ \"192.0.2.1\" ],
          firmwareStr:[ \"1.0.0 Build 20990101 Rel.00000\" ],
          hardwareStr:[ \"TL-SG108E 6.0\" ]
        };
        </script></html>"""

        vars = parse_script_variables(html)
        info = vars.get('info_ds')
        self.assertIsInstance(info, dict)
        self.assertEqual(info.get('descriStr'), ['TL-SG108E'])
        self.assertEqual(info.get('ipStr'), ['192.0.2.23'])

    def test_parse_multi_assignment_new_array_without_trailing_semicolon(self) -> None:
        # Matches what the switch serves: many assignments in one var statement,
        # sometimes without a trailing ';' at end-of-script.
        html = """<html><head><script type=text/javascript>
        var trunk_info=new Array(\"\",\" (LAG1)\"),state_info=new Array(\"Disabled\",\"Enabled\"),
        speed_info=new Array(\"Link Down\",\"Auto\"),flow_info=new Array(\"Off\",\"On\"),selState=new Array(0,1,0)
        </script></head></html>"""

        vars = parse_script_variables(html)
        self.assertEqual(vars.get('state_info'), ['Disabled', 'Enabled'])
        self.assertEqual(vars.get('flow_info'), ['Off', 'On'])
        self.assertEqual(vars.get('selState'), [0, 1, 0])


class TestTPLinkSG108EClient(TestCase):
    def test_supports_success(self) -> None:
        client = TPLinkSG108EClient('http://192.168.0.23', 'password')
        client._session = Mock()
        client._session.cookies = Mock()
        client._session.cookies.clear = Mock()

        root = Mock()
        root.status_code = 200

        sysinfo = Mock()
        sysinfo.status_code = 200
        sysinfo.text = """<html><script>var g_title = 'TL-SG108E';</script></html>"""

        login = Mock()
        login.status_code = 200

        client._session.get.side_effect = [root, sysinfo]
        client._session.post.return_value = login

        self.assertTrue(client.supports())

    def test_supports_by_hardware_str_with_custom_description(self) -> None:
        # Device Description is user-editable, hardwareStr is not.
        client = TPLinkSG108EClient('http://192.0.2.23', 'password')
        client._session = Mock()
        client._session.cookies = Mock()
        client._session.cookies.clear = Mock()

        root = Mock()
        root.status_code = 200

        sysinfo = Mock()
        sysinfo.status_code = 200
        sysinfo.text = """<html><script>
        var info_ds = { descriStr:[\"TPLink-Main-Switch\"], macStr:[\"02:00:00:00:00:01\"],
        firmwareStr:[\"1.0.0 Build 20230218 Rel.50633\"], hardwareStr:[\"TL-SG108E 6.0\"] };
        </script></html>"""

        login = Mock()
        login.status_code = 200

        client._session.get.side_effect = [root, sysinfo]
        client._session.post.return_value = login

        self.assertTrue(client.supports())

    def test_get_ipv4_status_from_ip_settings(self) -> None:
        client = TPLinkSG108EClient('http://192.168.0.23', 'password')
        client._session = Mock()

        ip_html = """<html><script>
        var ip_ds = { ipStr: ['192.168.1.1'], netmaskStr: ['255.255.255.0'],
        gatewayStr: ['192.168.1.254'], macStr: ['AA:BB:CC:DD:EE:FF'] };
        var tip = '';
        </script></html>"""
        resp = Mock()
        resp.status_code = 200
        resp.text = ip_html
        client._session.get.return_value = resp

        ipv4 = client.get_ipv4_status()
        self.assertEqual(ipv4.lan_ipv4_ipaddr, '192.168.1.1')
        self.assertEqual(ipv4.lan_ipv4_netmask, '255.255.255.0')
        self.assertEqual(ipv4.wan_ipv4_gateway, '192.168.1.254')
        self.assertEqual(ipv4.lan_macaddr.lower(), 'aa-bb-cc-dd-ee-ff')

    def test_get_ipv4_status_mac_falls_back_to_system_info(self) -> None:
        client = TPLinkSG108EClient('http://192.0.2.23', 'password')
        client._session = Mock()

        ip_html = """<html><script>
        var ip_ds = { state:1, vlan:1, maxVlan:4094, ipStr: [\"192.0.2.23\"], netmaskStr: [\"255.255.255.0\"],
        gatewayStr: [\"192.0.2.1\"] };
        </script></html>"""
        sys_html = """<html><script>
        var info_ds = { descriStr:[\"TL-SG108E\"], macStr:[\"02:00:00:00:00:01\"], ipStr:[\"192.0.2.23\"],
        netmaskStr:[\"255.255.255.0\"], gatewayStr:[\"192.0.2.1\"], firmwareStr:[\"1.0.0\"],
        hardwareStr:[\"TL-SG108E 6.0\"] };
        </script></html>"""

        ip_resp = Mock()
        ip_resp.status_code = 200
        ip_resp.text = ip_html

        sys_resp = Mock()
        sys_resp.status_code = 200
        sys_resp.text = sys_html

        def _get(url, *args, **kwargs):
            if url.endswith('/IpSettingRpm.htm'):
                return ip_resp
            if url.endswith('/SystemInfoRpm.htm'):
                return sys_resp
            raise AssertionError(f'unexpected url: {url}')

        client._session.get.side_effect = _get

        ipv4 = client.get_ipv4_status()
        # EUI48 stringifies with hyphens in this project.
        self.assertEqual(ipv4.lan_macaddr.lower(), '02-00-00-00-00-01')

    def test_get_status_aggregates_port_link_counts(self) -> None:
        client = TPLinkSG108EClient('http://192.0.2.23', 'password')

        # max_port_num ports, link_status is non-zero for link-up.
        # state=0 indicates disabled port and should be ignored.
        client.port_stats = Mock(return_value={
            'max_port_num': 8,
            'all_info': {
                'state': [1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
                'link_status': [6, 6, 0, 5, 5, 6, 5, 6, 0, 0],
            },
        })
        # The MAC lookup is best-effort and must not break the port counts.
        client.device_info = Mock(side_effect=Exception('system info unavailable'))

        status = client.get_status()
        self.assertEqual(status.wired_total, 8)
        # 7 ports link-up (one is down), disabled port ignored.
        self.assertEqual(status.clients_total, 6)
        self.assertIsNone(status.lan_macaddr)

    def test_get_status_populates_lan_macaddr(self) -> None:
        client = TPLinkSG108EClient('http://192.0.2.23', 'password')

        client.port_stats = Mock(return_value={
            'max_port_num': 8,
            'all_info': {
                'state': [1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
                'link_status': [6, 6, 0, 5, 5, 6, 5, 6, 0, 0],
            },
        })
        client.device_info = Mock(return_value={'macStr': '02:00:00:00:00:01'})

        status = client.get_status()
        # EUI48 stringifies with hyphens in this project.
        self.assertEqual(status.lan_macaddr.lower(), '02-00-00-00-00-01')

    def test_get_port_status_maps_live_tl_sg108e_v6_payloads(self) -> None:
        client = TPLinkSG108EClient('http://192.0.2.23', 'password')
        client.port_stats = Mock(return_value={
            'max_port_num': 8,
            'port_middle_num': 16,
            'all_info': {
                'state': [1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
                'link_status': [6, 6, 6, 6, 5, 0, 0, 0, 0, 0],
                'pkts': [
                    6790692, 0, 5572836, 1444,
                    1090232, 0, 4646114, 1443,
                    4990331, 0, 690965, 1443,
                    4147068, 0, 5933003, 1443,
                    87616, 0, 0, 1443,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0,
                ],
            },
            'state_info': ['Disabled', 'Enabled'],
            'link_info': [
                'Link Down', 'Auto', '10Half', '10Full',
                '100Half', '100Full', '1000Full', '',
            ],
        })
        client.port_settings = Mock(return_value={
            'max_port_num': 8,
            'port_middle_num': 16,
            'all_info': {
                'state': [1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
                'trunk_info': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                'spd_cfg': [1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
                'spd_act': [6, 6, 6, 6, 5, 0, 0, 0, 0, 0],
                'fc_cfg': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                'fc_act': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            'trunk_info': [
                '', ' (LAG1)', ' (LAG2)', ' (LAG3)', ' (LAG4)',
                ' (LAG5)', ' (LAG6)', ' (LAG7)', ' (LAG8)',
            ],
            'state_info': ['Disabled', 'Enabled'],
            'speed_info': [
                'Link Down', 'Auto', '10MH', '10MF',
                '100MH', '100MF', '1000MF', '',
            ],
            'flow_info': ['Off', 'On'],
        })

        ports = client.get_port_status()
        self.assertEqual(len(ports), 8)
        self.assertEqual([p.port for p in ports], [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertTrue(all(isinstance(p, PortStatus) for p in ports))

        port1 = ports[0]
        self.assertTrue(port1.enabled)
        self.assertTrue(port1.link_up)
        self.assertTrue(port1.auto_negotiation)
        self.assertIsNone(port1.configured_speed)
        self.assertIsNone(port1.configured_duplex)
        self.assertEqual(port1.negotiated_speed, 1000)
        self.assertEqual(port1.negotiated_duplex, 'full')
        self.assertFalse(port1.flow_control_enabled)
        self.assertFalse(port1.flow_control_active)
        self.assertIsNone(port1.lag)
        self.assertEqual(port1.tx_good_packets, 6790692)
        self.assertEqual(port1.tx_bad_packets, 0)
        self.assertEqual(port1.rx_good_packets, 5572836)
        self.assertEqual(port1.rx_bad_packets, 1444)

        port5 = ports[4]
        self.assertEqual(port5.negotiated_speed, 100)
        self.assertEqual(port5.negotiated_duplex, 'full')
        self.assertEqual(port5.tx_good_packets, 87616)
        self.assertEqual(port5.tx_bad_packets, 0)
        self.assertEqual(port5.rx_good_packets, 0)
        self.assertEqual(port5.rx_bad_packets, 1443)

        port6 = ports[5]
        self.assertTrue(port6.enabled)
        self.assertFalse(port6.link_up)
        self.assertIsNone(port6.negotiated_speed)
        self.assertIsNone(port6.negotiated_duplex)
        self.assertEqual(port6.tx_good_packets, 0)
        self.assertEqual(port6.tx_bad_packets, 0)
        self.assertEqual(port6.rx_good_packets, 0)
        self.assertEqual(port6.rx_bad_packets, 0)

        client.port_stats.assert_called_once()
        client.port_settings.assert_called_once()

    def test_get_port_status_fixed_mode_disabled_and_lag(self) -> None:
        client = TPLinkSG108EClient('http://192.0.2.23', 'password')
        client.port_stats = Mock(return_value={
            'max_port_num': 4,
            'all_info': {
                'state': [1, 0, 1, 1],
                'link_status': [6, 0, 2, 3],
                'pkts': [
                    10, 0, 20, 1,
                    0, 0, 0, 0,
                    30, 2, 40, 3,
                    50, 0, 60, 0,
                ],
            },
        })
        client.port_settings = Mock(return_value={
            'max_port_num': 4,
            'all_info': {
                'state': [1, 0, 1, 1],
                'trunk_info': [0, 0, 1, 0],
                'spd_cfg': [1, 1, 4, 6],
                'spd_act': [6, 0, 2, 6],
                'fc_cfg': [0, 0, 1, 0],
                'fc_act': [0, 0, 1, 0],
            },
        })

        ports = client.get_port_status()
        self.assertEqual(len(ports), 4)

        disabled = ports[1]
        self.assertFalse(disabled.enabled)
        self.assertFalse(disabled.link_up)
        self.assertTrue(disabled.auto_negotiation)
        self.assertIsNone(disabled.configured_speed)
        self.assertIsNone(disabled.configured_duplex)
        self.assertIsNone(disabled.lag)

        fixed_half = ports[2]
        self.assertTrue(fixed_half.enabled)
        self.assertTrue(fixed_half.link_up)
        self.assertFalse(fixed_half.auto_negotiation)
        self.assertEqual(fixed_half.configured_speed, 100)
        self.assertEqual(fixed_half.configured_duplex, 'half')
        self.assertEqual(fixed_half.negotiated_speed, 10)
        self.assertEqual(fixed_half.negotiated_duplex, 'half')
        self.assertTrue(fixed_half.flow_control_enabled)
        self.assertTrue(fixed_half.flow_control_active)
        self.assertEqual(fixed_half.lag, 1)

        fixed_full = ports[3]
        self.assertFalse(fixed_full.auto_negotiation)
        self.assertEqual(fixed_full.configured_speed, 1000)
        self.assertEqual(fixed_full.configured_duplex, 'full')
        self.assertEqual(fixed_full.negotiated_speed, 1000)
        self.assertEqual(fixed_full.negotiated_duplex, 'full')
        self.assertFalse(fixed_full.flow_control_enabled)
        self.assertFalse(fixed_full.flow_control_active)
        self.assertIsNone(fixed_full.lag)

    def test_get_port_status_short_and_malformed_arrays(self) -> None:
        client = TPLinkSG108EClient('http://192.0.2.23', 'password')
        client.port_stats = Mock(return_value={
            'max_port_num': 0,
            'all_info': {
                'state': [1],
                'link_status': [6],
                'pkts': [0, 5],
            },
        })
        client.port_settings = Mock(return_value={
            'max_port_num': 3,
            'all_info': {
                'state': [1],
                'trunk_info': ['bad'],
                'spd_cfg': [2],
                'spd_act': [3],
                'fc_cfg': [1],
                'fc_act': ['x'],
            },
        })

        ports = client.get_port_status()
        self.assertEqual(len(ports), 3)
        self.assertEqual([p.port for p in ports], [1, 2, 3])

        port1 = ports[0]
        self.assertTrue(port1.enabled)
        self.assertTrue(port1.link_up)
        self.assertFalse(port1.auto_negotiation)
        self.assertEqual(port1.configured_speed, 10)
        self.assertEqual(port1.configured_duplex, 'half')
        self.assertEqual(port1.negotiated_speed, 10)
        self.assertEqual(port1.negotiated_duplex, 'full')
        self.assertTrue(port1.flow_control_enabled)
        self.assertIsNone(port1.flow_control_active)
        self.assertIsNone(port1.lag)
        self.assertEqual(port1.tx_good_packets, 0)
        self.assertEqual(port1.tx_bad_packets, 5)
        self.assertIsNone(port1.rx_good_packets)
        self.assertIsNone(port1.rx_bad_packets)

        for port in ports[1:]:
            self.assertIsNone(port.enabled)
            self.assertIsNone(port.link_up)
            self.assertIsNone(port.auto_negotiation)
            self.assertIsNone(port.configured_speed)
            self.assertIsNone(port.configured_duplex)
            self.assertIsNone(port.negotiated_speed)
            self.assertIsNone(port.negotiated_duplex)
            self.assertIsNone(port.flow_control_enabled)
            self.assertIsNone(port.flow_control_active)
            self.assertIsNone(port.lag)
            self.assertIsNone(port.tx_good_packets)
            self.assertIsNone(port.tx_bad_packets)
            self.assertIsNone(port.rx_good_packets)
            self.assertIsNone(port.rx_bad_packets)


if __name__ == '__main__':
    main()
