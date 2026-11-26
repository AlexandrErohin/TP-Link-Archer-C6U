from unittest import TestCase, main
from unittest.mock import Mock, patch

from tplinkrouterc6u import TplinkDecoSGRouter, ClientException


class TestTplinkDecoSGRouter(TestCase):
    def test_supports_authorize_logout(self) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')
        with patch.object(client, 'authorize') as authorize, \
                patch.object(client, 'logout') as logout:
            self.assertTrue(client.supports())
            authorize.assert_called_once()
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
        self.assertEqual(login_headers.get('Content-Type'), 'application/json')
        self.assertIn('Referer', login_headers)

    def test_merge_keeps_json_request_body(self) -> None:
        path, data = TplinkDecoSGRouter._merge_path_and_body_params(
            'admin/network?form=wan_ipv4', '{"operation": "read"}')
        self.assertEqual(path, 'admin/network?form=wan_ipv4')
        self.assertEqual(data, '{"operation": "read"}')

    def test_supports_returns_false_when_authorize_fails(self) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')
        with patch.object(client, 'authorize', side_effect=ClientException('bad')), \
                patch.object(client, '_reset_session') as reset:
            self.assertFalse(client.supports())
            reset.assert_called_once()

    @patch('tplinkrouterc6u.client.deco_sg.post')
    def test_sg_request_uses_json_headers_with_sign_body(self, mock_post: Mock) -> None:
        client = TplinkDecoSGRouter('http://192.168.68.1', 'secret')
        client._logged = True
        client._stok = 'tok1'
        client._sysauth = 'abc123'
        client._hash = 'hash'
        client._seq = 1

        response = Mock()
        response.text = '{"data":"cipher"}'
        response.json.return_value = {'data': 'cipher'}
        mock_post.return_value = response

        with patch.object(client, '_aes_encrypt', return_value='enc'), \
                patch.object(client, '_build_request_signature', return_value='sig'), \
                patch.object(client, '_aes_decrypt',
                             return_value='{"error_code":0,"result":{"ok":true}}'):
            result = client._sg_request(
                'admin/network?form=wan_ipv4', '{"operation":"read"}')

        self.assertEqual(result, {'ok': True})
        call_kwargs = mock_post.call_args.kwargs
        headers = call_kwargs.get('headers') or {}
        self.assertEqual(headers.get('Content-Type'), 'application/json')
        self.assertIn('Referer', headers)
        self.assertTrue(str(call_kwargs.get('data', '')).startswith('sign='))


if __name__ == '__main__':
    main()
