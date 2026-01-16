from unittest import main
from unittest.mock import patch, Mock
from test_client_c6u import TestTPLinkClient
from tplinkrouterc6u import TplinkRouterV1_11, ClientException


class TestTPLinkClientV1_11(TestTPLinkClient):
    """Inherits all tests from TestTPLinkClient, using TplinkRouterV1_11."""

    router_class = TplinkRouterV1_11
    game_accelerator_path = 'admin/smart_network?form=game_accelerator&operation=loadDevice'
    openvpn_config_path = 'admin/openvpn?form=config&operation=read'
    pptpd_config_path = 'admin/pptpd?form=config&operation=read'
    vpn_uses_data_param = False

    # V1_11-specific tests only

    def test_supports_password_too_long(self) -> None:
        long_password = 'a' * 126
        client = TplinkRouterV1_11('http://192.168.0.1', long_password)
        self.assertFalse(client.supports())

    @patch('tplinkrouterc6u.client.c6u.EncryptionWrapper.rsa_encrypt')
    @patch('tplinkrouterc6u.client.c6u.post')
    def test_authorize_success(self, mock_post: Mock, mock_rsa: Mock) -> None:
        mock_rsa.return_value = 'encrypted_password_hex'

        keys_response = Mock()
        keys_response.json.return_value = {
            'success': True,
            'data': {
                'password': ['mock_nn_value', '010001']
            }
        }

        login_response = Mock()
        login_response.json.return_value = {
            'success': True,
            'data': {
                'stok': 'test_stok_12345'
            }
        }
        login_response.headers = {'set-cookie': 'sysauth=test_sysauth_cookie; path=/'}

        mock_post.side_effect = [keys_response, login_response]

        client = TplinkRouterV1_11('http://192.168.0.1', 'testpassword')
        client.authorize()

        self.assertTrue(client._logged)
        self.assertEqual(client._stok, 'test_stok_12345')
        self.assertEqual(client._sysauth, 'test_sysauth_cookie')
        self.assertEqual(mock_post.call_count, 2)

        first_call = mock_post.call_args_list[0]
        self.assertIn('login?form=keys', first_call[0][0])

        second_call = mock_post.call_args_list[1]
        self.assertIn('login?form=login', second_call[0][0])
        login_data = second_call[1]['data']
        self.assertTrue(login_data.startswith('operation=login&password='))

    @patch('tplinkrouterc6u.client.c6u.EncryptionWrapper.rsa_encrypt')
    @patch('tplinkrouterc6u.client.c6u.post')
    def test_authorize_failure(self, mock_post: Mock, mock_rsa: Mock) -> None:
        mock_rsa.return_value = 'encrypted_password_hex'

        keys_response = Mock()
        keys_response.json.return_value = {
            'success': True,
            'data': {
                'password': ['mock_nn_value', '010001']
            }
        }

        login_response = Mock()
        login_response.json.return_value = {
            'success': False,
            'data': {'errorcode': 'invalid password'}
        }
        login_response.headers = {}

        mock_post.side_effect = [keys_response, login_response]

        client = TplinkRouterV1_11('http://192.168.0.1', 'wrongpassword')

        with self.assertRaises(ClientException) as context:
            client.authorize()

        self.assertIn('Login failed', str(context.exception))
        self.assertFalse(client._logged)


if __name__ == '__main__':
    main()
