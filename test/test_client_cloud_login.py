from unittest import TestCase, main
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from tplinkrouterc6u import TplinkCloudLoginRouter, TplinkRouterProvider
from tplinkrouterc6u.common.exception import AuthorizeError


def _key_response() -> Mock:
    response = Mock()
    response.json.return_value = {
        'success': True,
        'data': {'username': 'owner@example.com', 'password': ['nnhex', '010001']},
    }
    return response


def _login_response(body: dict, cookie: str = '') -> Mock:
    response = Mock()
    response.status_code = 200
    response.text = str(body)
    response.json.return_value = body
    response.headers = {'set-cookie': cookie} if cookie else {}
    return response


class TestTplinkCloudLoginRouter(TestCase):
    @patch('tplinkrouterc6u.client.cloud_login.post')
    def test_supports_false_without_email(self, mock_post) -> None:
        client = TplinkCloudLoginRouter('http://192.168.0.1', 'secret', 'admin')
        self.assertFalse(client.supports())
        mock_post.assert_not_called()

    @patch('tplinkrouterc6u.client.cloud_login.post')
    def test_supports_reads_cloud_login_key(self, mock_post) -> None:
        mock_post.return_value = _key_response()

        client = TplinkCloudLoginRouter('http://192.168.0.1', 'secret', 'user@example.com')
        self.assertTrue(client.supports())

        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args.args[0],
                         'http://192.168.0.1/cgi-bin/luci/;stok=/login?form=cloud_login')
        self.assertEqual(mock_post.call_args.kwargs['data'], 'operation=read')
        self.assertEqual((client._pwdNN, client._pwdEE), ('nnhex', '010001'))

    @patch('tplinkrouterc6u.client.cloud_login.post')
    def test_supports_false_when_no_cloud_login_form(self, mock_post) -> None:
        response = Mock()
        response.text = '<html>404</html>'
        response.json.side_effect = ValueError('not json')
        mock_post.return_value = response

        client = TplinkCloudLoginRouter('http://192.168.0.1', 'secret', 'user@example.com')
        self.assertFalse(client.supports())

    @patch('tplinkrouterc6u.client.cloud_login.EncryptionWrapper.rsa_encrypt', return_value='cipherhex')
    @patch('tplinkrouterc6u.client.cloud_login.post')
    def test_authorize_posts_email_and_encrypted_password(self, mock_post, mock_rsa) -> None:
        mock_post.side_effect = [
            _key_response(),
            _login_response({'success': True, 'data': {'stok': 'tok'}}, 'sysauth=cookie; path=/cgi-bin/luci'),
        ]

        client = TplinkCloudLoginRouter('http://192.168.0.1', 'secret', 'user@example.com')
        client.authorize()

        self.assertTrue(client._logged)
        self.assertEqual(client._stok, 'tok')
        self.assertEqual(client._sysauth, 'cookie')
        mock_rsa.assert_called_once_with('secret', 'nnhex', '010001')
        self.assertEqual(mock_post.call_count, 2)
        self.assertEqual(mock_post.call_args.args[0],
                         'http://192.168.0.1/cgi-bin/luci/;stok=/login?form=cloud_login')
        self.assertEqual(parse_qs(mock_post.call_args.kwargs['data']), {
            'operation': ['login'],
            'username': ['user@example.com'],
            'password': ['cipherhex'],
        })

    @patch('tplinkrouterc6u.client.cloud_login.EncryptionWrapper.rsa_encrypt', return_value='cipherhex')
    @patch('tplinkrouterc6u.client.cloud_login.post')
    def test_authorize_wrong_password(self, mock_post, _mock_rsa) -> None:
        mock_post.side_effect = [
            _key_response(),
            _login_response({'errorcode': 'login failed', 'success': False,
                             'data': {'failureCount': 1, 'errorcode': '-5001', 'attemptsAllowed': 9}}),
        ]

        client = TplinkCloudLoginRouter('http://192.168.0.1', 'wrong', 'user@example.com')
        with self.assertRaises(AuthorizeError):
            client.authorize()
        self.assertFalse(client._logged)

    def test_provider_tries_cloud_login_first(self) -> None:
        self.assertEqual(next(iter(TplinkRouterProvider.get_clients())), TplinkCloudLoginRouter.__name__)


if __name__ == '__main__':
    main()
