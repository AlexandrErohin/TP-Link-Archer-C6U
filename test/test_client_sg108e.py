from unittest import TestCase, main
from unittest.mock import Mock

from tplinkrouterc6u import TPLinkSG108EClient
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
        var trunk_info=new Array(\"\",\" (LAG1)\"),state_info=new Array(\"Disabled\",\"Enabled\"),speed_info=new Array(\"Link Down\",\"Auto\"),flow_info=new Array(\"Off\",\"On\"),selState=new Array(0,1,0)
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

    def test_get_ipv4_status_from_ip_settings(self) -> None:
        client = TPLinkSG108EClient('http://192.168.0.23', 'password')
        client._session = Mock()

        ip_html = """<html><script>
        var ip_ds = { ipStr: ['192.168.1.1'], netmaskStr: ['255.255.255.0'], gatewayStr: ['192.168.1.254'], macStr: ['AA:BB:CC:DD:EE:FF'] };
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
        var ip_ds = { state:1, vlan:1, maxVlan:4094, ipStr: [\"192.0.2.23\"], netmaskStr: [\"255.255.255.0\"], gatewayStr: [\"192.0.2.1\"] };
        </script></html>"""
        sys_html = """<html><script>
        var info_ds = { descriStr:[\"TL-SG108E\"], macStr:[\"02:00:00:00:00:01\"], ipStr:[\"192.0.2.23\"], netmaskStr:[\"255.255.255.0\"], gatewayStr:[\"192.0.2.1\"], firmwareStr:[\"1.0.0\"], hardwareStr:[\"TL-SG108E 6.0\"] };
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

        status = client.get_status()
        self.assertEqual(status.wired_total, 8)
        # 7 ports link-up (one is down), disabled port ignored.
        self.assertEqual(status.clients_total, 6)


if __name__ == '__main__':
    main()
