"""Discovery is intentionally passive; authentication is limited to one client."""
from unittest import TestCase
from unittest.mock import Mock, patch

from tplinkrouterc6u.discovery import discover_router, DetectionError, DetectionResult
from tplinkrouterc6u.provider import TplinkRouterProvider
from tplinkrouterc6u.client.c6u import TplinkRouter


class TestPassiveDiscovery(TestCase):
    @patch('tplinkrouterc6u.discovery.post')
    def test_sg_certification_never_sends_credentials(self, post):
        response = Mock()
        response.json.return_value = {
            'data': {'certification': ['SG CLS L1 STAGE2']}}
        post.return_value = response
        result = discover_router('http://router', timeout=30)
        self.assertEqual(result.client_name, 'TplinkRouterSG')
        self.assertEqual(post.call_count, 1)
        self.assertEqual(post.call_args.kwargs['data'], 'operation=read')
        self.assertEqual(post.call_args.kwargs['timeout'], 5)

    @patch('tplinkrouterc6u.discovery.post')
    def test_v1_11_uses_read_only_key_length(self, post):
        config = Mock()
        config.json.return_value = {'data': {'certification': []}}
        keys = Mock()
        keys.json.return_value = {
            'data': {'password': ['A' * 512, '010001']}}
        post.side_effect = [config, keys]
        result = discover_router('router')
        self.assertEqual(result.client_name, 'TplinkRouterV1_11')
        self.assertEqual(post.call_count, 2)
        self.assertTrue(all(call.kwargs['data'] == 'operation=read'
                            for call in post.call_args_list))

    @patch('tplinkrouterc6u.discovery.post')
    def test_classic_key(self, post):
        config, keys = Mock(), Mock()
        config.json.return_value = {'data': {}}
        keys.json.return_value = {
            'data': {'password': ['A' * 256, '010001']}}
        post.side_effect = [config, keys]
        self.assertEqual(discover_router('router').client_name, 'TplinkRouter')

    @patch('tplinkrouterc6u.discovery.post')
    def test_unknown_key_fails_closed(self, post):
        config, keys = Mock(), Mock()
        config.json.return_value = {'data': {}}
        keys.json.return_value = {
            'data': {'password': ['not-hex', '010001']}}
        post.side_effect = [config, keys]
        self.assertIsNone(discover_router('router').client_name)

    @patch.object(TplinkRouterProvider, 'discover')
    def test_unknown_router_never_attempts_authentication(self, discover):
        discover.return_value = DetectionResult(None, 'unknown', 'no match')
        with patch('tplinkrouterc6u.client.sg.TplinkRouterSG.authorize') as auth:
            with self.assertRaises(DetectionError):
                TplinkRouterProvider.get_client_safe('router', 'bad-password')
            auth.assert_not_called()

    @patch.object(TplinkRouterProvider, 'discover')
    def test_auth_failure_does_not_try_another_client(self, discover):
        discover.return_value = DetectionResult(
            'TplinkRouterSG', 'high', 'SG certification')
        with patch('tplinkrouterc6u.client.sg.TplinkRouterSG.authorize',
                   side_effect=RuntimeError('invalid password')) as auth:
            with self.assertRaisesRegex(RuntimeError, 'invalid password'):
                TplinkRouterProvider.get_client_safe('router', 'bad-password')
            auth.assert_called_once()

    @patch.object(TplinkRouterProvider, 'discover')
    def test_classic_403_does_not_retry_login(self, discover):
        discover.return_value = DetectionResult(
            'TplinkRouter', 'medium', '1024-bit RSA key')
        denied = Mock(status_code=403, text='denied', headers={})
        denied.json.side_effect = ValueError('not JSON')
        with patch.object(TplinkRouter, '_request_pwd'), \
             patch.object(TplinkRouter, '_request_seq'), \
             patch.object(TplinkRouter, '_try_login',
                          return_value=denied) as login:
            with self.assertRaises(Exception):
                TplinkRouterProvider.get_client_safe('router', 'bad-password')
            login.assert_called_once()
