from json import dumps
from unittest import TestCase, main
from unittest.mock import Mock, patch

from Crypto.PublicKey import RSA

from tplinkrouterc6u import TplinkPGW2440Router, TplinkRouterProvider, Connection, Status, IPv4Status
from tplinkrouterc6u.client.pgw2440 import EncryptionWrapperNoPadding
from tplinkrouterc6u.common.exception import ClientException, ClientError

HOST = 'http://192.168.0.250'

# Shapes as returned by a PGW2440 v1.0 (firmware 1.0.4). MACs, IPs, names, SSIDs and keys are made up.
STATUS_IPV4 = {'lan_ipv4_ipaddr': '192.168.0.250', 'lan_ipv4_netmask': '255.255.255.0'}
WLAN_STATUS = {
    'wireless_2g_ssid': 'home', 'wireless_2g_enable': 'on', 'wireless_2g_disabled': 'off',
    'wireless_2g_channel': 5, 'auto_2g': 0, 'wireless_2g_macaddr': '02-00-00-00-00-01',
    'wireless_2g_encryption': 'psk', 'wireless_2g_pwd': 'secret',
    'wireless_5g_ssid': 'home', 'wireless_5g_enable': 'off', 'wireless_5g_disabled': 'on',
    'wireless_5g_channel': 48, 'auto_5g': 0, 'wireless_5g_macaddr': '02-00-00-00-00-02',
    'wireless_5g_encryption': 'psk', 'wireless_5g_pwd': 'secret',
}
STATISTICS = [
    {'mac': 'AA-BB-CC-00-00-01', 'type': '2.4GHz', 'encryption': ' ', 'rxpkts': '120', 'txpkts': '80',
     'ip': '192.168.0.30', 'devType': 'pc', 'devName': 'laptop'},
    {'mac': 'AA-BB-CC-00-00-02', 'type': '5GHz', 'encryption': ' ', 'rxpkts': '', 'txpkts': None,
     'ip': '192.168.0.31', 'devType': 'phone', 'devName': 'phone'},
    {'type': '2.4GHz', 'devName': 'no mac'},
]


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


def raw_rsa_decrypt(hex_blocks: str, key: RSA.RsaKey) -> str:
    size = key.size_in_bytes() * 2
    out = b''
    for pos in range(0, len(hex_blocks), size):
        block = pow(int(hex_blocks[pos:pos + size], 16), key.d, key.n)
        out += block.to_bytes(key.size_in_bytes(), 'big').rstrip(b'\0')
    return out.decode()


class TestEncryptionWrapperNoPadding(TestCase):
    def test_signature_round_trip(self) -> None:
        key = RSA.generate(1024)
        nn, ee = format(key.n, 'x'), format(key.e, 'x')
        wrapper = EncryptionWrapperNoPadding()

        sign = wrapper.get_signature(1234, True, 'abcdef', nn, ee)
        self.assertEqual(raw_rsa_decrypt(sign, key), '{}&h=abcdef&s=1234'.format(wrapper._get_aes_string()))

        sign = wrapper.get_signature(99, False, 'abcdef', nn, ee)
        self.assertEqual(raw_rsa_decrypt(sign, key), 'h=abcdef&s=99')

    def test_blocks_are_64_characters(self) -> None:
        key = RSA.generate(1024)
        nn, ee = format(key.n, 'x'), format(key.e, 'x')
        wrapper = EncryptionWrapperNoPadding()
        # k=<16>&i=<16>&h=<32>&s=<n> is longer than 64 characters: two blocks.
        sign = wrapper.get_signature(1, True, 'a' * 32, nn, ee)
        self.assertEqual(len(sign), 2 * key.size_in_bytes() * 2)


class TestTplinkPGW2440Router(TestCase):
    def _client(self) -> TplinkPGW2440Router:
        client = TplinkPGW2440Router(HOST, 'password')
        client._logged = True
        client._seq = '100'
        client.nn, client.ee = 'CD34', '010001'
        client._encryption = Mock()
        client._encryption.aes_encrypt.return_value = 'encrypted-body'
        client._encryption.get_signature.return_value = 'signature'
        return client

    @patch('tplinkrouterc6u.client.pgw2440.post')
    def test_supports_reads_only_unauthenticated_forms(self, mock_post: Mock) -> None:
        mock_post.side_effect = [
            response({'success': True, 'timeout': False, 'data': {'password': ['AB12', '010001']}}),
            response({'success': True, 'timeout': False,
                      'data': {'model': 'PGW2440', 'hardware_version': 'PGW2440 v1.0', 'firmware_version': '1.0.4'}}),
        ]
        self.assertTrue(TplinkPGW2440Router(HOST, 'password').supports())
        urls = [call.args[0] for call in mock_post.call_args_list]
        self.assertEqual(urls, [HOST + '/login?form=keys', HOST + '/admin/firmware?form=get_firmware_info'])
        for call in mock_post.call_args_list:
            self.assertEqual(call.kwargs['data'], 'operation=read')
            self.assertEqual(call.kwargs['headers']['Referer'], HOST + '/')

    @patch('tplinkrouterc6u.client.pgw2440.post', return_value=response(text='<h1>Not Found</h1>', status_code=404))
    def test_supports_false_on_other_devices(self, _mock_post: Mock) -> None:
        self.assertFalse(TplinkPGW2440Router(HOST, 'password').supports())

    def test_supports_false_for_long_password(self) -> None:
        with patch('tplinkrouterc6u.client.pgw2440.post') as mock_post:
            self.assertFalse(TplinkPGW2440Router(HOST, 'x' * 200).supports())
            mock_post.assert_not_called()

    def test_prepare_data_hash_is_md5_of_password(self) -> None:
        client = self._client()
        client.username = 'admin'
        self.assertEqual(client._prepare_data('operation=read'), {'sign': 'signature', 'data': 'encrypted-body'})
        client._encryption.get_signature.assert_called_once_with(
            100 + len('encrypted-body'), False, '5f4dcc3b5aa765d61d8327deb882cf99', 'CD34', '010001')

    @patch('tplinkrouterc6u.client.pgw2440.post')
    def test_authorize(self, mock_post: Mock) -> None:
        client = TplinkPGW2440Router(HOST, 'password')
        client._encryption = Mock()
        client._encryption.rsa_encrypt.return_value = 'crypted'
        client._encryption.aes_encrypt.return_value = 'encrypted-body'
        client._encryption.get_signature.return_value = 'signature'
        client._encryption.aes_decrypt.return_value = dumps({'success': True, 'timeout': False})
        mock_post.side_effect = [
            response({'success': True, 'timeout': False, 'data': {'password': ['AB12', '010001']}}),
            response({'success': True, 'timeout': False, 'data': {'key': ['CD34', '010001'], 'seq': '555'}}),
            response({'data': 'encrypted-login-response'}),
        ]

        client.authorize()

        self.assertTrue(client._logged)
        login = mock_post.call_args_list[2]
        self.assertEqual(login.args[0], HOST + '/login?form=login')
        self.assertEqual(login.kwargs['data'], {'sign': 'signature', 'data': 'encrypted-body'})
        client._encryption.aes_encrypt.assert_called_once_with('operation=login&password=crypted&confirm=true')
        client._encryption.get_signature.assert_called_once_with(
            555 + len('encrypted-body'), True, '5f4dcc3b5aa765d61d8327deb882cf99', 'CD34', '010001')

    @patch('tplinkrouterc6u.client.pgw2440.post')
    def test_authorize_plain_error(self, mock_post: Mock) -> None:
        client = TplinkPGW2440Router(HOST, 'password')
        mock_post.side_effect = [
            response({'success': True, 'timeout': False, 'data': {'password': ['AB12', '010001']}}),
            response({'success': True, 'timeout': False, 'data': {'key': ['CD34', '010001'], 'seq': '555'}}),
            response({'data': {'success': False, 'errorcode': 'timeout'}}),
        ]
        with patch.object(client._encryption, 'rsa_encrypt', return_value='crypted'), \
                patch.object(client._encryption, 'get_signature', return_value='signature'):
            with self.assertRaises(ClientException):
                client.authorize()
        self.assertFalse(client._logged)

    def test_request_requires_authorize(self) -> None:
        with self.assertRaises(ClientException):
            TplinkPGW2440Router(HOST, 'password').request('admin/wlan_status', 'operation=read')

    @patch('tplinkrouterc6u.client.pgw2440.post')
    def test_request_decrypts(self, mock_post: Mock) -> None:
        client = self._client()
        client._encryption.aes_decrypt.return_value = dumps(
            {'success': True, 'timeout': False, 'data': {'lan_ipv4_ipaddr': '192.168.0.250'}})
        mock_post.return_value = response({'data': 'encrypted-response'})

        self.assertEqual(client.request('admin/network?form=status_ipv4', 'operation=read'),
                         {'lan_ipv4_ipaddr': '192.168.0.250'})
        call = mock_post.call_args
        self.assertEqual(call.args[0], HOST + '/admin/network?form=status_ipv4')
        self.assertEqual(call.kwargs['data'], {'sign': 'signature', 'data': 'encrypted-body'})
        self.assertNotIn('cookies', call.kwargs)

    @patch('tplinkrouterc6u.client.pgw2440.post')
    def test_request_error(self, mock_post: Mock) -> None:
        client = self._client()
        mock_post.return_value = response({'data': {'success': False, 'errorcode': 'timeout'}})
        with self.assertRaises(ClientError):
            client.request('admin/network?form=status_ipv4', 'operation=read')
        self.assertEqual(client.request('admin/network?form=status_ipv4', 'operation=read', ignore_errors=True),
                         {'success': False, 'errorcode': 'timeout'})

    @patch('tplinkrouterc6u.client.pgw2440.post')
    def test_get_firmware_is_plain(self, mock_post: Mock) -> None:
        mock_post.return_value = response({'success': True, 'timeout': False, 'data': {
            'model': 'PGW2440', 'hardware_version': 'PGW2440 v1.0', 'firmware_version': '1.0.4 Build 20240830'}})
        firmware = self._client().get_firmware()
        self.assertEqual((firmware.model, firmware.hardware_version, firmware.firmware_version),
                         ('PGW2440', 'PGW2440 v1.0', '1.0.4 Build 20240830'))

    def _status_client(self, forms: dict) -> tuple[TplinkPGW2440Router, list]:
        client = self._client()
        calls = []

        def request(path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False):
            calls.append((path, data))
            if path not in forms:
                raise ClientError('missing')
            return forms[path]

        client.request = request  # type: ignore[method-assign]
        return client, calls

    def test_get_status(self) -> None:
        client, calls = self._status_client({'admin/network?form=status_ipv4': STATUS_IPV4,
                                             'admin/wlan_status': WLAN_STATUS,
                                             'admin/wireless?form=statistics': STATISTICS})
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.lan_ipv4_addr, '192.168.0.250')
        self.assertEqual(status.lan_macaddr, '02-00-00-00-00-01')
        self.assertTrue(status.wifi_2g_enable)
        self.assertFalse(status.wifi_5g_enable)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.clients_total, 2)
        self.assertEqual(
            [(d.type, d.macaddr, d.ipaddr, d.hostname, d.packets_received, d.packets_sent) for d in status.devices],
            [
                (Connection.HOST_2G, 'AA-BB-CC-00-00-01', '192.168.0.30', 'laptop', 120, 80),
                (Connection.HOST_5G, 'AA-BB-CC-00-00-02', '192.168.0.31', 'phone', None, None),
            ],
        )
        self.assertIn(('admin/wireless?form=statistics', 'operation=load'), calls)

    def test_get_status_without_optional_forms(self) -> None:
        client, _calls = self._status_client({})
        status = client.get_status()
        self.assertIsNone(status.lan_macaddr)
        self.assertIsNone(status.wifi_2g_enable)
        self.assertEqual(status.devices, [])

    def test_get_ipv4_status(self) -> None:
        client, _calls = self._status_client({'admin/network?form=status_ipv4': STATUS_IPV4})
        status = client.get_ipv4_status()
        self.assertIsInstance(status, IPv4Status)
        self.assertEqual(status.lan_ipv4_ipaddr, '192.168.0.250')
        self.assertEqual(status.lan_ipv4_netmask, '255.255.255.0')

    def test_reboot_and_logout(self) -> None:
        client = self._client()
        client.request = Mock()  # type: ignore[method-assign]
        client.reboot()
        client.request.assert_called_once_with('admin/reboot.json', 'operation=write', ignore_response=True)

        client.request.reset_mock()
        client.logout()
        client.request.assert_called_once_with('logout', 'operation=write', ignore_response=True)
        self.assertFalse(client._logged)
        client.logout()
        client.request.assert_called_once()

    def test_set_wifi_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError):
            self._client().set_wifi(Connection.HOST_2G, False)

    def test_provider_tries_it_first(self) -> None:
        self.assertEqual(next(iter(TplinkRouterProvider.get_clients())), TplinkPGW2440Router.__name__)


if __name__ == '__main__':
    main()
