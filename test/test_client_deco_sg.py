from hashlib import md5
from json import dumps
from unittest import TestCase, main
from unittest.mock import Mock, patch

from tplinkrouterc6u import TplinkDecoSGRouter, ClientException
from tplinkrouterc6u.client.deco_sg import _MERCUSYS_JSON_SEP


class TestTplinkDecoSGRouter(TestCase):
    def test_supports_probes_wan_ipv4(self) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')
        client._aes_key = '1234567890123456'
        client._aes_iv = '6543210987654321'
        client._hash = md5(b'adminsecret').hexdigest()
        client._seq = 100
        client._nn = 'ab' * 64
        client._ee = '010001'
        client._pwdNN = 'cd' * 64
        client._pwdEE = '010001'
        client._stok = '1234abcd'
        client._logged = True
        client._sysauth = 'cookie'

        wan = {'wan': {'ip_info': {'ip': '10.0.0.2'}}, 'lan': {'ip_info': {'ip': '192.168.68.1'}}}

        with patch.object(client, '_request_pwd_keys'), \
                patch.object(client, '_request_auth_keys'), \
                patch.object(client, 'authorize') as authorize, \
                patch.object(client, 'logout') as logout, \
                patch.object(client, 'request', return_value=wan) as request:
            self.assertTrue(client.supports())
            authorize.assert_called_once()
            request.assert_called_once_with(
                'admin/network?form=wan_ipv4',
                dumps({'operation': 'read'}, separators=_MERCUSYS_JSON_SEP))
            logout.assert_called_once()

    def test_login_payload_uses_deco_json(self) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')
        payload = client._get_login_payload('encrypted_hex')
        self.assertIn('"operation":"login"', payload)
        self.assertIn('"params":{"password":"encrypted_hex"}', payload)

    def test_extract_stok_from_result_block(self) -> None:
        stok = TplinkDecoSGRouter._extract_stok({'error_code': 0, 'result': {'stok': 'abcd'}})
        self.assertEqual(stok, 'abcd')

    @patch('tplinkrouterc6u.client.deco_sg.post')
    def test_authorize_accepts_deco_login_envelope(self, mock_post: Mock) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')

        def fake_envelope(response_json):
            response = Mock()
            response.text = ''
            response.json.return_value = response_json
            return response

        login_response = Mock()
        login_response.text = '{"data":"cipher"}'
        login_response.status_code = 200
        login_response.json.return_value = {'data': 'cipher'}
        login_response.headers = {'set-cookie': 'sysauth=abc123; path=/'}

        mock_post.side_effect = [
            fake_envelope({'result': {'password': ['cd' * 64, '010001']}}),
            fake_envelope({'result': {'seq': 55, 'key': ['ab' * 64, '010001']}}),
            login_response,
        ]
        with patch.object(TplinkDecoSGRouter, '_rsa_v15_encrypt', return_value='pwd'), \
                patch('tplinkrouterc6u.client.deco_sg.EncryptionWrapper.rsa_encrypt',
                      return_value='pwd'), \
                patch.object(client, '_aes_encrypt', return_value='enc'), \
                patch.object(client, '_build_login_signature', return_value='sig'), \
                patch.object(client, '_aes_decrypt',
                             return_value='{"error_code":0,"result":{"stok":"tok1"}}'):
            client.authorize()
        self.assertTrue(client._logged)
        self.assertEqual(client._stok, 'tok1')
        self.assertEqual(client._sysauth, 'abc123')
        login_headers = mock_post.call_args_list[-1].kwargs.get('headers') or {}
        self.assertEqual(login_headers.get('Content-Type'),
                         'application/x-www-form-urlencoded')

    def test_merge_keeps_json_request_body(self) -> None:
        path, data = TplinkDecoSGRouter._merge_path_and_body_params(
            'admin/network?form=wan_ipv4', '{"operation": "read"}')
        self.assertEqual(path, 'admin/network?form=wan_ipv4')
        self.assertEqual(data, '{"operation": "read"}')

    def test_supports_returns_false_when_wan_ipv4_fails(self) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')
        with patch.object(client, '_request_pwd_keys'), \
                patch.object(client, '_request_auth_keys'), \
                patch.object(client, 'authorize'), \
                patch.object(client, 'request', side_effect=ClientException('bad')):
            self.assertFalse(client.supports())

    def test_signed_form_headers_use_urlencoded(self) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')
        headers = client._signed_form_headers()
        self.assertEqual(headers['Content-Type'], 'application/x-www-form-urlencoded')
        self.assertIn('Referer', headers)


if __name__ == '__main__':
    main()
