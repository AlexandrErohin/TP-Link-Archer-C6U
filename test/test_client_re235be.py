from json import dumps
from unittest import TestCase, main
from unittest.mock import Mock, patch

from macaddress import EUI48

from tplinkrouterc6u import (
    TplinkRE235BERouter, TplinkRouter, TplinkRouterProvider, Connection, Status, IPv4Status,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError

HOST = 'http://192.168.0.254'
REFERER = HOST + '/webpages/index.html'
LOGIN_REFERER = HOST + '/webpages/login.html'

# Shapes as returned by an RE235BE v1.0 (firmware 1.0.16) in access point mode.
# All MAC addresses, IP addresses and names are made up.
AP_STATUS = {
    'wireless_2g_encryption': True, 'show2gFlag': True, 'mlo_enable': 'on', 'phyconn': 'connected',
    'wireless_5g_enable': 'on', 'wireless_2g_enable': 'on', 'wirelessCount': 2, 'opMode': 'ap',
    'show5gFlag': True, 'internet_status': 'connected', 'wireless_5g_encryption': True,
    'wirelessGrid': [
        {'mac': 'AA-BB-CC-00-00-01', 'type': '2.4GHz', 'name': 'sensor', 'conn_type': 'wireless',
         'rxrate': 54, 'txrate': 65, 'ipaddr': '192.168.0.20', 'ip': '192.168.0.20'},
        {'mac': 'AA-BB-CC-00-00-02', 'type': '5GHz', 'name': 'phone', 'conn_type': 'wireless',
         'rxrate': 866, 'txrate': 1200, 'ipaddr': '192.168.0.21', 'ip': '192.168.0.21'},
    ],
}
GUEST = [
    {'mac': 'AA-BB-CC-00-00-03', 'type': '2.4GHz', 'name': 'guest', 'conn_type': 'wireless',
     'rxrate': 65, 'txrate': 72, 'ipaddr': '192.168.0.22', 'ip': '192.168.0.22'},
]
# lan_ipv4 has no lan_macaddr / lan_ip on this firmware.
LAN_IPV4 = {
    'mask_type': '255.255.255.0', 'ipaddr': '192.168.0.254', 'lan_gw': '192.168.0.1',
    'old_ipaddr': '192.168.0.254', 'pri_dns': '192.168.0.1', 'lan_type': 'static',
    'macaddr': '02-00-00-00-00-AA', 'snd_dns': '', 'custom_value': '',
}
STATUS_DEVICE = {'wired_dhcp': '1', 'wired_ip': '192.168.0.254', 'wired_type': '0'}
STATUS_IPV4 = {
    'lan_ipv4_netmask': '255.255.255.0', 'lan_macaddr': '02-00-00-00-00-AA',
    'lan_ipv4_ipaddr': '192.168.0.254', 'lan_ipv4_dhcp_enable': 'Off',
}
PERF = {'mem_usage': 0.42, 'cpu_usage': 0.03}


def response(json_data=None, text: str = '', status_code: int = 200) -> Mock:
    resp = Mock()
    resp.status_code = status_code
    if json_data is None:
        resp.json.side_effect = ValueError('Expecting value')
        resp.text = text
    else:
        resp.json.return_value = json_data
        resp.text = dumps(json_data)
    return resp


class TestTplinkRE235BERouter(TestCase):
    def _client(self) -> TplinkRE235BERouter:
        client = TplinkRE235BERouter(HOST, 'password')
        client._logged = True
        client._stok = 'stok-token'
        client._sysauth = 'sysauth-token'
        return client

    def test_headers_have_referer(self) -> None:
        client = TplinkRE235BERouter(HOST, 'password')
        self.assertEqual(client._headers_request['Referer'], REFERER)
        self.assertEqual(client._headers_login['Referer'], LOGIN_REFERER)
        self.assertFalse(client._logged)
        self.assertEqual(client._stok, '')

    @patch('tplinkrouterc6u.client.re235be.post')
    def test_request_pwd_and_seq_send_referer(self, mock_post: Mock) -> None:
        mock_post.side_effect = [
            response({'success': True, 'data': {'password': ['AB12', '010001'], 'mode': 'ap', 'username': ''}}),
            response({'success': True, 'data': {'key': ['CD34', '010001'], 'seq': 123456}}),
        ]
        client = TplinkRE235BERouter(HOST, 'password')
        client._request_pwd()
        client._request_seq()

        self.assertEqual((client._pwdNN, client._pwdEE), ('AB12', '010001'))
        self.assertEqual((client.nn, client.ee, client._seq), ('CD34', '010001', 123456))
        urls = [call.args[0] for call in mock_post.call_args_list]
        self.assertEqual(urls, [
            HOST + '/cgi-bin/luci/;stok=/login?form=keys',
            HOST + '/cgi-bin/luci/;stok=/login?form=auth',
        ])
        for call in mock_post.call_args_list:
            self.assertEqual(call.kwargs['headers']['Referer'], LOGIN_REFERER)
            self.assertEqual(call.kwargs['params'], {'operation': 'read'})

    @patch('tplinkrouterc6u.client.re235be.post', return_value=response(text='<h1>Bad Request</h1>', status_code=400))
    def test_request_pwd_bad_request_raises(self, _mock_post: Mock) -> None:
        client = TplinkRE235BERouter(HOST, 'password')
        with self.assertRaises(ClientException):
            client._request_pwd()

    @patch('tplinkrouterc6u.client.re235be.post', return_value=response(text='<h1>Bad Request</h1>', status_code=400))
    def test_supports_false_without_login_when_keys_fail(self, _mock_post: Mock) -> None:
        client = TplinkRE235BERouter(HOST, 'password')
        client.authorize = Mock()  # type: ignore[method-assign]
        self.assertFalse(client.supports())
        client.authorize.assert_not_called()

    def test_supports_false_for_long_password(self) -> None:
        client = TplinkRE235BERouter(HOST, 'x' * 200)
        client._request_pwd = Mock()  # type: ignore[method-assign]
        self.assertFalse(client.supports())
        client._request_pwd.assert_not_called()

    def test_supports_true_when_ap_status_ok_and_form_all_fails(self) -> None:
        client = TplinkRE235BERouter(HOST, 'password')
        client._request_pwd = Mock()  # type: ignore[method-assign]
        client.authorize = Mock()  # type: ignore[method-assign]
        client.logout = Mock()  # type: ignore[method-assign]

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/status?form=ap_status':
                return AP_STATUS
            if path == 'admin/status?form=all':
                raise ClientError('500 attempt to index global wlan')
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        self.assertTrue(client.supports())
        client.authorize.assert_called_once()
        client.logout.assert_not_called()

    def test_supports_false_when_form_all_works(self) -> None:
        client = TplinkRE235BERouter(HOST, 'password')
        client._request_pwd = Mock()  # type: ignore[method-assign]
        client.authorize = Mock()  # type: ignore[method-assign]
        client.logout = Mock()  # type: ignore[method-assign]
        client.request = Mock(return_value=AP_STATUS)  # type: ignore[method-assign]
        self.assertFalse(client.supports())
        client.logout.assert_called_once()

    @patch('tplinkrouterc6u.client.c6u.TplinkEncryption.authorize')
    def test_authorize_keeps_session_from_supports(self, mock_authorize: Mock) -> None:
        self._client().authorize()
        mock_authorize.assert_not_called()

        TplinkRE235BERouter(HOST, 'password').authorize()
        mock_authorize.assert_called_once()

    @patch('tplinkrouterc6u.client.c6u.post')
    def test_request_is_encrypted_and_sends_referer(self, mock_post: Mock) -> None:
        client = self._client()
        client._seq = '100'
        client.nn, client.ee = 'CD34', '010001'
        client._encryption = Mock()
        client._encryption.aes_encrypt.return_value = 'encrypted-body'
        client._encryption.get_signature.return_value = 'signature'
        client._encryption.aes_decrypt.return_value = dumps({'success': True, 'data': PERF})
        mock_post.return_value = response({'data': 'encrypted-response'})

        self.assertEqual(client.request('admin/status?form=perf', 'operation=read'), PERF)

        call = mock_post.call_args
        self.assertEqual(call.args[0], HOST + '/cgi-bin/luci/;stok=stok-token/admin/status?form=perf')
        self.assertEqual(call.kwargs['data'], {'sign': 'signature', 'data': 'encrypted-body'})
        self.assertEqual(call.kwargs['headers']['Referer'], REFERER)
        self.assertEqual(call.kwargs['cookies'], {'sysauth': 'sysauth-token'})
        client._encryption.aes_encrypt.assert_called_once_with('operation=read')

    def test_get_status(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            forms = {
                'admin/status?form=ap_status': AP_STATUS,
                'admin/network?form=lan_ipv4': LAN_IPV4,
                'admin/status?form=status_device': STATUS_DEVICE,
                'admin/status?form=guest': GUEST,
                'admin/network?form=status_ipv4': STATUS_IPV4,
                'admin/status?form=perf': PERF,
            }
            if path == 'admin/extend?form=guest_settings':
                raise ClientError('500')
            return forms[path]

        client.request = request  # type: ignore[method-assign]
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.lan_macaddr, '02-00-00-00-00-AA')
        self.assertEqual(status.lan_macaddress, EUI48('02-00-00-00-00-AA'))
        self.assertEqual(status.lan_ipv4_addr, '192.168.0.254')
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertIsNone(status.guest_2g_enable)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 1)
        self.assertEqual(status.clients_total, 3)
        self.assertEqual(status.cpu_usage, 0.03)
        self.assertEqual(status.mem_usage, 0.42)
        self.assertEqual(
            [(d.type, d.macaddr, d.ipaddr, d.hostname, d.rx_rate, d.tx_rate) for d in status.devices],
            [
                (Connection.HOST_2G, 'AA-BB-CC-00-00-01', '192.168.0.20', 'sensor', 54, 65),
                (Connection.HOST_5G, 'AA-BB-CC-00-00-02', '192.168.0.21', 'phone', 866, 1200),
                (Connection.GUEST_2G, 'AA-BB-CC-00-00-03', '192.168.0.22', 'guest', 65, 72),
            ],
        )

    def test_get_status_skips_status_ipv4_when_lan_ipv4_is_complete(self) -> None:
        client = self._client()
        calls = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            calls.append(path)
            if path == 'admin/status?form=ap_status':
                return AP_STATUS
            if path == 'admin/network?form=lan_ipv4':
                return {'lan_macaddr': '02-00-00-00-00-BB', 'lan_ip': '192.168.0.253'}
            raise ClientError('missing')

        client.request = request  # type: ignore[method-assign]
        status = client.get_status()

        self.assertEqual(status.lan_macaddr, '02-00-00-00-00-BB')
        self.assertEqual(status.lan_ipv4_addr, '192.168.0.253')
        self.assertNotIn('admin/network?form=status_ipv4', calls)

    def test_get_status_without_status_ipv4(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/status?form=ap_status':
                return AP_STATUS
            raise ClientError('missing')

        client.request = request  # type: ignore[method-assign]
        status = client.get_status()

        self.assertIsNone(status.lan_macaddr)
        self.assertEqual(len(status.devices), 2)

    def test_get_ipv4_status(self) -> None:
        client = self._client()

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            if path == 'admin/network?form=lan_ipv4':
                return LAN_IPV4
            if path == 'admin/status?form=status_device':
                return STATUS_DEVICE
            if path == 'admin/network?form=status_ipv4':
                return STATUS_IPV4
            raise AssertionError(path)

        client.request = request  # type: ignore[method-assign]
        ipv4 = client.get_ipv4_status()

        self.assertIsInstance(ipv4, IPv4Status)
        self.assertEqual(ipv4.lan_macaddr, '02-00-00-00-00-AA')
        self.assertEqual(ipv4.lan_macaddress, EUI48('02-00-00-00-00-AA'))
        self.assertEqual(ipv4.lan_ipv4_ipaddr, '192.168.0.254')

    def test_get_ipv4_status_skips_status_ipv4_when_lan_ipv4_is_complete(self) -> None:
        client = self._client()
        calls = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            calls.append(path)
            if path == 'admin/network?form=lan_ipv4':
                return {'lan_macaddr': '02-00-00-00-00-BB', 'lan_ip': '192.168.0.253'}
            raise ClientError('missing')

        client.request = request  # type: ignore[method-assign]
        ipv4 = client.get_ipv4_status()

        self.assertEqual(ipv4.lan_macaddr, '02-00-00-00-00-BB')
        self.assertEqual(ipv4.lan_ipv4_ipaddr, '192.168.0.253')
        self.assertNotIn('admin/network?form=status_ipv4', calls)

    def test_provider_tries_after_classic_luci(self) -> None:
        names = list(TplinkRouterProvider.get_clients())
        self.assertIn(TplinkRE235BERouter.__name__, names)
        self.assertGreater(names.index(TplinkRE235BERouter.__name__), names.index(TplinkRouter.__name__))


if __name__ == '__main__':
    main()
