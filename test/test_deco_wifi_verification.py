# Added 2026-11-24: unit coverage for verified Deco WLAN writes; see LICENSE.
from copy import deepcopy
from json import loads
from unittest import TestCase, main
from unittest.mock import Mock, patch

from requests.exceptions import ReadTimeout

from tplinkrouterc6u import (
    Connection, TPLinkDecoClient, TplinkDecoSGRouter, TplinkDecoE4RRouter,
    ClientError, WifiWriteResult, WifiVerificationError,
    WifiWriteNotObserved, WifiVerificationUnavailable, WifiWriteRejected,
)


BANDS = {
    Connection.HOST_2G: ('band2_4', 'host'),
    Connection.GUEST_2G: ('band2_4', 'guest'),
    Connection.HOST_5G: ('band5_1', 'host'),
    Connection.GUEST_5G: ('band5_1', 'guest'),
    Connection.HOST_6G: ('band6', 'host'),
    Connection.GUEST_6G: ('band6', 'guest'),
}
SECRET = 'private-ssid-password-session-token'


def wlan_state(wifi=Connection.GUEST_2G, value=True):
    band, network = BANDS[wifi]
    return {band: {network: {'enable': value, 'ssid': SECRET, 'password': SECRET}}}


def reply(result=None, error_code=0):
    response = Mock()
    response.text = SECRET
    response.json.return_value = {'data': {'error_code': error_code, 'result': result}}
    return response


class DecoWifiVerificationTests(TestCase):
    def setUp(self):
        self.logger = Mock()
        self.client = TPLinkDecoClient('http://router.invalid', SECRET, logger=self.logger)
        self.client._logged = True
        self.client._stok = SECRET
        self.client._sysauth = SECRET
        # Keep the real request envelope validation and HTTP boundary. Only
        # cryptography and network I/O are replaced, with synthetic unit data.
        self.client._prepare_data = Mock(side_effect=lambda value: value)
        self.client._decrypt_response = Mock(side_effect=lambda data: data['data'])
        self.post_patcher = patch('tplinkrouterc6u.client.c6u.post')
        self.post = self.post_patcher.start()
        self.addCleanup(self.post_patcher.stop)
        self.sleep_patcher = patch('tplinkrouterc6u.client.deco.sleep')
        self.sleep = self.sleep_patcher.start()
        self.addCleanup(self.sleep_patcher.stop)

    def payloads(self):
        return [loads(call.kwargs['data']) for call in self.post.call_args_list]

    def assert_one_write(self, expected_reads):
        payloads = self.payloads()
        self.assertEqual([item['operation'] for item in payloads],
                         ['write'] + ['read'] * expected_reads)
        self.assertTrue(all(call.args[0].endswith('/admin/wireless?form=wlan')
                            for call in self.post.call_args_list))

    def test_all_six_networks_use_only_the_original_minimal_payload(self):
        for wifi, (band, network) in BANDS.items():
            for enable in (True, False):
                with self.subTest(wifi=wifi, enable=enable):
                    self.post.reset_mock()
                    other = {key: {'host': {'enable': False}, 'guest': {'enable': True}}
                             for key in ('band2_4', 'band5_1', 'band6')}
                    other[band][network]['enable'] = enable
                    before = deepcopy(other)
                    self.post.side_effect = [reply({}), reply(other)]
                    result = self.client.set_wifi_verified(wifi, enable, poll_interval=0)
                    self.assertIsInstance(result, WifiWriteResult)
                    self.assertEqual((result.wifi, result.enable), (wifi, enable))
                    self.assertIs(result.states[wifi], enable)
                    self.assertEqual(len(result.states), 6)
                    self.assertEqual(self.payloads()[0], {
                        'operation': 'write', 'params': {band: {network: {'enable': enable}}}})
                    self.assertEqual(other, before)
                    self.assert_one_write(1)

    def test_raw_write_reply_can_be_unreadable_when_read_confirms_state(self):
        malformed = Mock(text=SECRET)
        malformed.json.side_effect = ValueError(SECRET)
        self.post.side_effect = [malformed, reply(wlan_state())]
        result = self.client.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertIs(result.states[Connection.GUEST_2G], True)
        self.assert_one_write(1)
        self.logger.debug.assert_not_called()
        self.assertIs(self.client._logger, self.logger)

    def test_write_timeout_is_not_repeated_when_read_confirms_state(self):
        self.post.side_effect = [ReadTimeout(SECRET), reply(wlan_state())]
        self.client.authorize = Mock(side_effect=AssertionError('No reauthorization'))
        self.client.request = Mock(side_effect=AssertionError('No automatic request wrapper'))
        self.client._retry_request = Mock(side_effect=AssertionError('No automatic retries'))
        self.client._request_with_reauth = Mock(side_effect=AssertionError('No automatic reauthorization'))
        self.client.get_status = Mock(side_effect=AssertionError('No WAN reads'))
        result = self.client.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertIs(result.states[Connection.GUEST_2G], True)
        self.assert_one_write(1)
        self.client.authorize.assert_not_called()
        self.client.request.assert_not_called()
        self.client._retry_request.assert_not_called()
        self.client._request_with_reauth.assert_not_called()
        self.client.get_status.assert_not_called()

    def test_client_error_does_not_trigger_a_second_write(self):
        self.post.side_effect = [ClientError(SECRET), reply(wlan_state(value=False))]
        with self.assertRaises(WifiWriteNotObserved) as raised:
            self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=1)
        self.assert_one_write(1)
        self.assertEqual(raised.exception.error_type, 'ClientError')
        self.assertEqual(dict(raised.exception.latest_states), {Connection.GUEST_2G: False})

    def test_successful_json_without_changed_state_is_not_success(self):
        self.post.side_effect = [reply({})] + [reply(wlan_state(value=False)) for _ in range(3)]
        with self.assertRaises(WifiWriteNotObserved) as raised:
            self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=3, poll_interval=0.25)
        self.assertEqual(dict(raised.exception.latest_states), {Connection.GUEST_2G: False})
        self.assert_one_write(3)
        self.assertEqual(self.sleep.call_count, 2)
        self.sleep.assert_called_with(0.25)

    def test_read_retries_are_bounded_and_can_eventually_confirm(self):
        self.post.side_effect = [reply({}), ReadTimeout(SECRET), ClientError(SECRET), reply(wlan_state())]
        result = self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=3, poll_interval=0)
        self.assertIs(result.states[Connection.GUEST_2G], True)
        self.assert_one_write(3)

    def test_all_read_failures_raise_unavailable_and_keep_errors_safe(self):
        self.post.side_effect = [ReadTimeout(SECRET)] + [ClientError(SECRET) for _ in range(2)]
        with self.assertRaises(WifiVerificationUnavailable) as raised:
            self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=2, poll_interval=0)
        error = raised.exception
        self.assertEqual(dict(error.latest_states), {})
        self.assertEqual(error.error_type, 'ClientError')
        self.assertNotIn(SECRET, str(error))
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        self.assert_one_write(2)
        self.logger.debug.assert_not_called()

    def test_latest_safe_observed_states_are_available_after_failure(self):
        first = wlan_state(value=False)
        latest = wlan_state(value=False)
        latest['band5_1'] = {'host': {'enable': 'off', 'password': SECRET}}
        self.post.side_effect = [reply({}), reply(first), reply(latest)]
        with self.assertRaises(WifiWriteNotObserved) as raised:
            self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=2, poll_interval=0)
        self.assertEqual(dict(raised.exception.latest_states), {
            Connection.GUEST_2G: False, Connection.HOST_5G: False})
        self.assertNotIn(SECRET, repr(raised.exception.latest_states))
        with self.assertRaises(TypeError):
            raised.exception.latest_states[Connection.GUEST_2G] = True

    def test_explicit_rejection_is_distinct_even_if_state_already_matches(self):
        self.post.side_effect = [reply({'ssid': SECRET}, error_code=-1), reply(wlan_state())]
        with self.assertRaises(WifiWriteRejected) as raised:
            self.client.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertEqual(raised.exception.error_type, 'RouterRejected')
        self.assertEqual(dict(raised.exception.latest_states), {Connection.GUEST_2G: True})
        self.assertNotIn(SECRET, str(raised.exception))
        self.assert_one_write(1)

    def test_explicit_rejection_survives_unavailable_reads(self):
        self.post.side_effect = [reply({}, error_code=42), ReadTimeout(SECRET)]
        with self.assertRaises(WifiWriteRejected):
            self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=1)
        self.assert_one_write(1)

    def test_unknown_failure_envelope_is_not_assumed_explicit_rejection(self):
        self.post.side_effect = [reply({}, error_code='unknown'), reply(wlan_state())]
        result = self.client.set_wifi_verified(Connection.GUEST_2G, True)
        self.assertIs(result.states[Connection.GUEST_2G], True)

    def test_read_rejection_is_not_a_wifi_write_rejection(self):
        self.post.side_effect = [reply({}), reply({}, error_code=-2)]
        with self.assertRaises(WifiVerificationUnavailable):
            self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=1)
        self.assert_one_write(1)

    def test_recognized_states_are_normalized_without_truthiness(self):
        for raw, expected in ((True, True), (False, False), (0, False), (1, True),
                              ('on', True), ('off', False), ('true', True), ('false', False),
                              ('ON', True), ('FALSE', False)):
            with self.subTest(raw=raw):
                self.post.reset_mock()
                self.post.side_effect = [reply({}), reply(wlan_state(value=raw))]
                result = self.client.set_wifi_verified(Connection.GUEST_2G, expected)
                self.assertIs(result.states[Connection.GUEST_2G], expected)
                with self.assertRaises(TypeError):
                    result.states[Connection.GUEST_2G] = not expected

    def test_invalid_observed_values_never_turn_into_true_or_false(self):
        for raw in (None, '', 'unknown', '0', '1', ' off ', 2, -1, 0.0, 1.0, [], {}, object()):
            with self.subTest(raw=raw):
                self.post.reset_mock()
                self.post.side_effect = [reply({}), reply(wlan_state(value=raw))]
                with self.assertRaises(WifiVerificationUnavailable) as raised:
                    self.client.set_wifi_verified(Connection.GUEST_2G, False, attempts=1)
                self.assertNotIn(Connection.GUEST_2G, raised.exception.latest_states)
                self.assert_one_write(1)

    def test_malformed_wlan_shapes_are_unavailable(self):
        for snapshot in (None, [], 'unexpected', {}, {'band2_4': []},
                         {'band2_4': {'guest': True}}, {'band2_4': {'guest': {}}}):
            with self.subTest(snapshot=snapshot):
                self.post.side_effect = [reply({}), reply(snapshot)]
                with self.assertRaises(WifiVerificationUnavailable):
                    self.client.set_wifi_verified(Connection.GUEST_2G, True, attempts=1)

    def test_parameters_are_validated_before_any_transport(self):
        cases = [
            {'wifi': Connection.IOT_2G}, {'wifi': Connection.HOST_MLO},
            {'wifi': Connection.WIRED}, {'wifi': Connection.UNKNOWN}, {'wifi': 'GUEST_2G'}, {'wifi': []},
            *({'enable': value} for value in (0, 1, 'on', 'off', None, [], {})),
            *({'attempts': value} for value in (0, -1, True, 1.0, '3')),
            *({'poll_interval': value} for value in (-1, True, '1', float('inf'), float('nan'))),
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                kwargs = {'wifi': Connection.GUEST_2G, 'enable': True, **changes}
                with self.assertRaises(ValueError):
                    self.client.set_wifi_verified(**kwargs)
        self.post.assert_not_called()

    def test_other_deco_transports_are_rejected_before_any_write(self):
        for client_type in (TplinkDecoSGRouter, TplinkDecoE4RRouter):
            with self.subTest(client_type=client_type):
                client = client_type('http://router.invalid', SECRET)
                self.assertIs(client.supports_verified_wifi, False)
                with self.assertRaises(WifiVerificationUnavailable) as raised:
                    client.set_wifi_verified(Connection.GUEST_2G, True)
                self.assertEqual(raised.exception.error_type, 'UnsupportedTransport')
        self.post.assert_not_called()

    def test_verification_support_includes_classic_subclasses_without_transport_override(self):
        class ClassicSubclass(TPLinkDecoClient):
            pass

        self.assertIs(self.client.supports_verified_wifi, True)
        self.assertIs(ClassicSubclass('http://router.invalid', SECRET).supports_verified_wifi, True)
        self.post.assert_not_called()

    def test_verified_off_stays_strictly_false_or_unknown_after_normal_polling(self):
        network = {
            'wan': {'ip_info': {'mac': '02:00:00:00:00:01', 'ip': '192.0.2.2', 'gateway': '192.0.2.1'}},
            'lan': {'ip_info': {'mac': '02:00:00:00:00:02', 'ip': '192.168.68.1'}},
        }
        fields = ('wifi_2g_enable', 'guest_2g_enable', 'wifi_5g_enable',
                  'guest_5g_enable', 'wifi_6g_enable', 'guest_6g_enable')
        expected_paths = ['admin/wireless?form=wlan', 'admin/wireless?form=wlan',
                          'admin/network?form=wan_ipv4', 'admin/network?form=performance',
                          'admin/wireless?form=wlan', 'admin/client?form=client_list']
        for raw, expected in (('false', False), ('off', False), (0, False), ('unknown', None), (None, None)):
            with self.subTest(raw=raw):
                self.post.reset_mock()
                snapshot = {band: {'host': {'enable': raw}, 'guest': {'enable': raw}}
                            for band in ('band2_4', 'band5_1', 'band6')}
                self.post.side_effect = [reply({}), reply(wlan_state(value=False)),
                                         reply(network), reply({'mem_usage': 0.2, 'cpu_usage': 0.1}),
                                         reply(snapshot), reply({'client_list': []})]
                result = self.client.set_wifi_verified(Connection.GUEST_2G, False, attempts=1)
                self.assertIs(result.states[Connection.GUEST_2G], False)
                status = self.client.get_status()
                for field in fields:
                    self.assertIs(getattr(status, field), expected)
                self.assertEqual(len(self.post.call_args_list), len(expected_paths))
                for call, path in zip(self.post.call_args_list, expected_paths):
                    self.assertTrue(call.args[0].endswith('/' + path))

    def test_classic_set_wifi_keeps_its_existing_request_contract(self):
        self.client.request = Mock()
        result = self.client.set_wifi(Connection.GUEST_5G, False)
        self.assertIsNone(result)
        self.client.request.assert_called_once_with(
            'admin/wireless?form=wlan',
            '{"operation": "write", "params": {"band5_1": {"guest": {"enable": false}}}}')
        self.post.assert_not_called()

    def test_safe_exception_constructor_discards_unrecognized_values(self):
        error = WifiWriteNotObserved({Connection.GUEST_2G: False, 'ssid': SECRET,
                                      Connection.GUEST_5G: 'off'}, 'ClientError')
        self.assertIsInstance(error, WifiVerificationError)
        self.assertEqual(dict(error.latest_states), {Connection.GUEST_2G: False})
        self.assertNotIn(SECRET, repr(error))


if __name__ == '__main__':
    main()
