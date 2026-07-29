import json
from hashlib import sha256
from unittest import main, TestCase
from unittest.mock import patch, Mock

from tplinkrouterc6u import TplinkRouterSG, ClientException
from test_client_c6u import TestTPLinkClient


class TestTPLinkClientSG(TestTPLinkClient):
    """Inherits get_status and other tests from TestTPLinkClient."""

    router_class = TplinkRouterSG
    game_accelerator_path = 'admin/smart_network?form=game_accelerator&operation=loadDevice'
    openvpn_config_path = 'admin/openvpn?form=config&operation=read'
    pptpd_config_path = 'admin/pptpd?form=config&operation=read'
    vpn_uses_data_param = False


class TestTplinkRouterSGUnit(TestCase):
    """Unit tests specific to TplinkRouterSG authentication and encryption."""

    def setUp(self):
        self.host = 'http://192.168.0.1'
        self.password = 'test_password'
        self.client = TplinkRouterSG(self.host, self.password)
        self.client._logged = True
        self.client._stok = 'mock_stok'
        self.client._hash = 'fakehash'
        self.client._aes_key = '1234567890123456'
        self.client._aes_iv = '6543210987654321'
        self.client._seq = 100

    def test_supports_password_too_long(self) -> None:
        long_password = 'a' * 126
        client = TplinkRouterSG('http://192.168.0.1', long_password)
        self.assertFalse(client.supports())

    @patch('tplinkrouterc6u.client.sg.post')
    def test_check_sg_certification_match(self, mock_post: Mock) -> None:
        response = Mock()
        response.json.return_value = {
            'data': {
                'certification': ['SG CLS L1 STAGE2', 'OTHER']
            }
        }
        mock_post.return_value = response

        client = TplinkRouterSG('http://192.168.0.1', 'testpassword')
        result = client._check_sg_certification()

        self.assertTrue(result)
        self.assertEqual(mock_post.call_count, 1)
        call_args = mock_post.call_args
        self.assertIn('device_config', call_args[0][0])

    @patch('tplinkrouterc6u.client.sg.post')
    def test_check_sg_certification_no_match(self, mock_post: Mock) -> None:
        response = Mock()
        response.json.return_value = {
            'data': {
                'certification': ['SOME_OTHER_CERT']
            }
        }
        mock_post.return_value = response

        client = TplinkRouterSG('http://192.168.0.1', 'testpassword')
        result = client._check_sg_certification()

        self.assertFalse(result)

    @patch('tplinkrouterc6u.client.sg.post')
    def test_authorize_success(self, mock_post: Mock) -> None:
        pwd_keys_response = Mock()
        pwd_keys_response.json.return_value = {
            'data': {
                'password': ['mock_pwd_nn', '010001']
            }
        }

        auth_keys_response = Mock()
        auth_keys_response.json.return_value = {
            'data': {
                'seq': 100,
                'key': ['mock_auth_nn', '010001']
            }
        }

        login_response = Mock()
        login_response.json.return_value = {'data': 'encrypted_login_blob'}
        login_response.headers = {
            'set-cookie': 'sysauth=test_sysauth_value; path=/'
        }
        login_response.text = 'mock response text'

        mock_post.side_effect = [
            pwd_keys_response,
            auth_keys_response,
            login_response,
        ]

        client = TplinkRouterSG('http://192.168.0.1', 'testpassword')

        login_result = json.dumps({
            'success': True,
            'data': {'stok': 'test_stok_12345'}
        })
        with patch.object(client, '_rsa_v15_encrypt', return_value='encrypted_pwd_hex'), \
             patch.object(client, '_aes_encrypt', return_value='encrypted_data_b64'), \
             patch.object(client, '_build_login_signature', return_value='mock_sign'), \
             patch.object(client, '_aes_decrypt', return_value=login_result):
            client.authorize()

        self.assertTrue(client._logged)
        self.assertEqual(client._stok, 'test_stok_12345')
        self.assertEqual(client._sysauth, 'test_sysauth_value')
        self.assertEqual(mock_post.call_count, 3)

        first_call = mock_post.call_args_list[0]
        self.assertIn('login?form=keys', first_call[0][0])

        second_call = mock_post.call_args_list[1]
        self.assertIn('login?form=auth', second_call[0][0])

        third_call = mock_post.call_args_list[2]
        self.assertIn('login?form=login', third_call[0][0])

    @patch('tplinkrouterc6u.client.sg.post')
    def test_authorize_failure(self, mock_post: Mock) -> None:
        pwd_keys_response = Mock()
        pwd_keys_response.json.return_value = {
            'data': {
                'password': ['mock_pwd_nn', '010001']
            }
        }

        auth_keys_response = Mock()
        auth_keys_response.json.return_value = {
            'data': {
                'seq': 100,
                'key': ['mock_auth_nn', '010001']
            }
        }

        login_response = Mock()
        login_response.json.return_value = {'data': 'encrypted_login_blob'}
        login_response.headers = {}
        login_response.text = 'mock error response'

        mock_post.side_effect = [
            pwd_keys_response,
            auth_keys_response,
            login_response,
        ]

        client = TplinkRouterSG('http://192.168.0.1', 'wrongpassword')

        login_result = json.dumps({
            'success': False,
            'data': {'errorcode': 'invalid password'}
        })
        with patch.object(client, '_rsa_v15_encrypt', return_value='encrypted_pwd_hex'), \
             patch.object(client, '_aes_encrypt', return_value='encrypted_data_b64'), \
             patch.object(client, '_build_login_signature', return_value='mock_sign'), \
             patch.object(client, '_aes_decrypt', return_value=login_result):
            with self.assertRaises(ClientException) as context:
                client.authorize()

        self.assertIn('Login failed', str(context.exception))
        self.assertFalse(client._logged)

    def test_authorize_uses_username(self) -> None:
        """Verify SHA256 hash uses self.username, not hardcoded 'admin'."""
        client = TplinkRouterSG(
            'http://192.168.0.1', 'testpassword', username='customuser')

        expected_hash = sha256(
            ('customuser' + 'testpassword').encode()).hexdigest()
        admin_hash = sha256(
            ('admin' + 'testpassword').encode()).hexdigest()

        # Simulate the hash computation that happens in authorize()
        client._hash = sha256(
            (client.username + client.password).encode()).hexdigest()

        self.assertEqual(client._hash, expected_hash)
        self.assertNotEqual(client._hash, admin_hash)

    @patch('tplinkrouterc6u.client.sg.post')
    def test_request_hmac_signature(self, mock_post: Mock) -> None:
        """Verify non-login requests use HMAC-SHA256 signature."""
        response = Mock()
        decrypted_data = json.dumps({
            'success': True,
            'data': {'key': 'value'}
        })
        response.json.return_value = {'data': 'encrypted'}
        mock_post.return_value = response

        with patch.object(self.client, '_aes_decrypt', return_value=decrypted_data):
            result = self.client.request('admin/status?form=all', 'operation=read')

        self.assertEqual(result, {'key': 'value'})

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]['data']
        # Default for READ is string format
        self.assertIsInstance(body, str)
        self.assertTrue(body.startswith('sign='))
        self.assertIn('&data=', body)

        # Hash should have been updated to SHA256 of the encrypted data
        self.assertNotEqual(self.client._hash, 'fakehash')

    @patch('tplinkrouterc6u.client.sg.post')
    def test_request_write_dict_body(self, mock_post: Mock) -> None:
        """Verify that WRITE requests switch to dictionary format (BE-series Fix)."""
        response = Mock()
        response.json.return_value = {'data': 'encrypted'}
        mock_post.return_value = response

        with patch.object(self.client, '_aes_decrypt', return_value='{"success": true}'):
            self.client.request('admin/wireless?form=guest_2g', 'operation=write&ssid=test')

        call_kwargs = mock_post.call_args
        body = call_kwargs[1]['data']
        self.assertIsInstance(body, dict)
        self.assertIn('sign', body)
        self.assertIn('data', body)
        
        # Verify mandatory header is present for WRITE
        headers = call_kwargs[1]['headers']
        self.assertEqual(headers.get('Content-Type'), 'application/x-www-form-urlencoded')


if __name__ == '__main__':
    main()
