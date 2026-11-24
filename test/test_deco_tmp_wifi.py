from unittest import TestCase
from unittest.mock import Mock, patch

from tplinkrouterc6u import (
    Connection, TPLinkDecoClient, TplinkDecoSGRouter,
    WifiVerificationUnavailable, WifiWriteNotObserved, WifiWriteRejected,
)
from tplinkrouterc6u.client.deco_tmp import DecoTMPError, DecoTMPRejected


USERNAME = 'a' * 40
PIN = 'b' * 64
SECRET = 'synthetic-secret-never-in-errors'


def wlan(value, wifi=Connection.GUEST_2G):
    band = {Connection.GUEST_2G: 'band2_4', Connection.GUEST_5G: 'band5_1',
            Connection.GUEST_6G: 'band6'}[wifi]
    return {band: {'host': {'enable': True}, 'guest': {'enable': value, 'password': SECRET}}}


class DecoTMPWifiVerificationTests(TestCase):
    def setUp(self):
        self.router = TPLinkDecoClient('http://router.invalid:80', SECRET)
        self.router.configure_tmp_wifi(username_sha1=USERNAME, host_key_sha256=PIN)
        self.router._wifi_request_once = Mock(side_effect=AssertionError('No HTTP write fallback'))
        self.patcher = patch('tplinkrouterc6u.client.deco.DecoTMPTransport')
        self.factory = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.transport = self.factory.return_value.__enter__.return_value
        self.sleep = patch('tplinkrouterc6u.client.deco.sleep').start()
        self.addCleanup(patch.stopall)

    def test_configuration_is_pure_and_requires_explicit_valid_identity_and_pin(self):
        router = TPLinkDecoClient('router.invalid', SECRET)
        from tplinkrouterc6u.client.deco_tmp import DecoTMPTransport
        with patch('tplinkrouterc6u.client.deco_tmp.socket.create_connection') as connect, \
                patch('tplinkrouterc6u.client.deco.DecoTMPTransport', side_effect=DecoTMPTransport):
            for username, pin in [('admin', PIN), (USERNAME, ''), ('', PIN)]:
                with self.subTest(username=username, pin=pin):
                    with self.assertRaises(ValueError):
                        router.configure_tmp_wifi(username_sha1=username, host_key_sha256=pin)
            router.configure_tmp_wifi(username_sha1=USERNAME, host_key_sha256=PIN)
            connect.assert_not_called()

    def test_sg_cannot_enable_the_classic_tmp_path(self):
        router = TplinkDecoSGRouter('router.invalid', SECRET)
        with self.assertRaises(ValueError):
            router.configure_tmp_wifi(username_sha1=USERNAME, host_key_sha256=PIN)

    def test_verified_guest_change_reads_before_and_after_one_write(self):
        for wifi in (Connection.GUEST_2G, Connection.GUEST_5G, Connection.GUEST_6G):
            with self.subTest(wifi=wifi):
                self.transport.reset_mock()
                self.transport.get_wlan.side_effect = [wlan(False, wifi), wlan(True, wifi)]
                result = self.router.set_wifi_verified(wifi, True)
                self.assertIs(result.states[wifi], True)
                self.transport.set_guest_wifi.assert_called_once_with(wifi, True)
                self.assertEqual(self.transport.get_wlan.call_count, 2)
                self.router._wifi_request_once.assert_not_called()
                self.factory.return_value.__exit__.assert_called()

    def test_already_requested_observed_state_does_not_actuate(self):
        self.transport.get_wlan.return_value = wlan(True)
        result = self.router.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertIs(result.states[Connection.GUEST_2G], True)
        self.transport.set_guest_wifi.assert_not_called()

    def test_unrecognized_initial_state_refuses_to_write(self):
        self.transport.get_wlan.return_value = wlan('unknown')
        with self.assertRaises(WifiVerificationUnavailable):
            self.router.set_wifi_verified(Connection.GUEST_2G, True)
        self.transport.set_guest_wifi.assert_not_called()

    def test_write_ack_is_not_confirmation_and_cannot_trigger_replay(self):
        self.transport.get_wlan.return_value = wlan(False)
        self.transport.set_guest_wifi.return_value = {'error_code': 0}
        with self.assertRaises(WifiWriteNotObserved) as caught:
            self.router.set_wifi_verified(Connection.GUEST_2G, True, attempts=2, poll_interval=0)
        self.assertIs(caught.exception.latest_states[Connection.GUEST_2G], False)
        self.transport.set_guest_wifi.assert_called_once()
        self.assertEqual(self.transport.get_wlan.call_count, 3)

    def test_uncertain_write_can_succeed_only_when_readback_confirms(self):
        self.transport.get_wlan.side_effect = [wlan(False), DecoTMPError('TMPNotConnected')]
        self.transport.set_guest_wifi.side_effect = DecoTMPError('TMPTimeout')
        self.router._wifi_request_once = Mock(return_value=wlan(True))
        result = self.router.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertIs(result.states[Connection.GUEST_2G], True)
        self.transport.set_guest_wifi.assert_called_once()
        self.assertEqual(self.transport.get_wlan.call_count, 1)
        self.router._wifi_request_once.assert_called_once_with({'operation': 'read'})

    def test_explicit_rejection_remains_failure_even_if_readback_matches(self):
        self.transport.get_wlan.side_effect = [wlan(False), wlan(True)]
        self.transport.set_guest_wifi.side_effect = DecoTMPRejected(3)
        self.router._wifi_request_once = Mock(return_value=wlan(True))
        with self.assertRaises(WifiWriteRejected):
            self.router.set_wifi_verified(Connection.GUEST_2G, True)
        self.transport.set_guest_wifi.assert_called_once()

    def test_authentication_failure_is_sanitized_without_web_fallback(self):
        self.factory.return_value.__enter__.side_effect = DecoTMPError('SSHConnectionFailed')
        with self.assertRaises(WifiVerificationUnavailable) as caught:
            self.router.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.transport.set_guest_wifi.assert_not_called()
        self.router._wifi_request_once.assert_not_called()

    def test_channel_loss_after_write_is_unverified_and_not_replayed(self):
        self.transport.get_wlan.side_effect = [wlan(False), DecoTMPError('TMPConnectionClosed'),
                                               DecoTMPError('TMPNotConnected')]
        self.router._wifi_request_once = Mock(side_effect=DecoTMPError('HTTPUnavailable'))
        with self.assertRaises(WifiVerificationUnavailable):
            self.router.set_wifi_verified(Connection.GUEST_2G, True, attempts=2, poll_interval=0)
        self.transport.set_guest_wifi.assert_called_once()
        self.assertEqual(self.transport.get_wlan.call_count, 2)
        self.assertEqual(self.router._wifi_request_once.call_args_list[0].args, ({'operation': 'read'},))

    def test_reload_channel_loss_can_be_confirmed_through_existing_http_session(self):
        self.transport.get_wlan.side_effect = [wlan(False), DecoTMPError('TMPConnectionClosed')]
        self.router._wifi_request_once = Mock(return_value=wlan(True))
        result = self.router.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertIs(result.states[Connection.GUEST_2G], True)
        self.transport.set_guest_wifi.assert_called_once()
        self.router._wifi_request_once.assert_called_once_with({'operation': 'read'})

    def test_rejected_http_read_cannot_confirm_a_timed_out_app_write(self):
        self.transport.get_wlan.return_value = wlan(False)
        self.transport.set_guest_wifi.side_effect = DecoTMPError('TMPTimeout')
        response = wlan(True)
        response['error_code'] = -1
        self.router._wifi_request_once = Mock(return_value=response)
        with self.assertRaises(WifiVerificationUnavailable):
            self.router.set_wifi_verified(Connection.GUEST_2G, True, attempts=2, poll_interval=0)
        self.transport.set_guest_wifi.assert_called_once()
        self.assertEqual(self.router._wifi_request_once.call_count, 2)

    def test_host_control_keeps_the_existing_verified_http_path(self):
        self.router._wifi_request_once = Mock(side_effect=[{}, {'band2_4': {'host': {'enable': False}}}])
        result = self.router.set_wifi_verified(Connection.HOST_2G, False)
        self.assertIs(result.states[Connection.HOST_2G], False)
        self.factory.assert_not_called()
        self.assertEqual(self.router._wifi_request_once.call_count, 2)
