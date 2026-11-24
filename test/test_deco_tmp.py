"""Offline transport tests with synthetic peer frames and no network access."""

import base64
import hashlib
import json
import socket
import struct
import unittest
import zlib
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tplinkrouterc6u.client import deco_tmp
from tplinkrouterc6u.client.deco_tmp import DecoTMPError, DecoTMPRejected, DecoTMPTransport
from tplinkrouterc6u.common.package_enum import Connection


KEY = b'unit-test-public-key-blob'
PIN = hashlib.sha256(KEY).hexdigest()
USERNAME = '1' * 40
PASSWORD = 'unit-test-password'
TOKEN = b'0123456789abcdef0123456789abcdef'


def peer_frame(opcode, transaction, body=b'', packet_type=5, status=0,
               total=None, offset=0, body_checksum=None, sequence=1):
    """Build peer fixtures using the independent seeded-CRC protocol formula."""
    if body_checksum is None:
        body_checksum = zlib.crc32(body) & 0xFFFFFFFF
    payload = struct.pack('>BBHBBHIII', 1, 2, opcode, packet_type, status, transaction,
                          body_checksum, len(body) if total is None else total, offset) + body
    header = struct.pack('>BBBBHHI', 1, 1, 5, 0, len(payload), 0, sequence)
    checksum = zlib.crc32(header + b'\0' * 4 + payload, 0xE63EB2DE) & 0xFFFFFFFF
    return header + struct.pack('>I', checksum) + payload


def json_response(value, opcode=0x4009, transaction=0, **kwargs):
    return peer_frame(opcode, transaction, json.dumps(value, separators=(',', ':')).encode(), **kwargs)


class Channel:
    def __init__(self, incoming=b'', chunk_size=None):
        self.incoming = bytearray(incoming)
        self.sent = []
        self.chunk_size = chunk_size
        self.closed = False
        self.send_error = None
        self.recv_error = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(data)
        if self.send_error is not None:
            raise self.send_error

    def recv(self, size):
        if self.recv_error is not None:
            raise self.recv_error
        if self.chunk_size is not None:
            size = min(size, self.chunk_size)
        result = bytes(self.incoming[:size])
        del self.incoming[:size]
        return result

    def close(self):
        self.closed = True


def client(pin=PIN, **kwargs):
    return DecoTMPTransport('router.example.test', USERNAME, PASSWORD, pin, **kwargs)


def connected(incoming=b'', **kwargs):
    instance = client()
    channel = Channel(incoming, **kwargs)
    instance._channel = channel
    return instance, channel


def sent_business(frame):
    fields = struct.unpack_from('>BBHBBHIII', frame, 16)
    return {'opcode': fields[2], 'type': fields[3], 'transaction': fields[5],
            'offset': fields[8], 'body': frame[36:]}


class TestDecoTMPTransport(unittest.TestCase):
    def test_alloc_frame_matches_fixed_protocol_vector(self):
        payload = bytes.fromhex('0102000102000000000000000000000000000000')
        expected = bytes.fromhex(
            '01010500001400000000000150384e94'
            '0102000102000000000000000000000000000000')
        self.assertEqual(DecoTMPTransport._business(1, 2, 0), payload)
        self.assertEqual(DecoTMPTransport._frame(payload, 1), expected)

    def test_open_checks_pin_before_single_password_auth_and_allocates(self):
        channel = Channel(peer_frame(1, 0, TOKEN), chunk_size=2)
        ssh = Mock()
        ssh.get_remote_server_key.return_value.asbytes.return_value = KEY
        ssh.open_channel.return_value = channel
        sock = Mock()
        order = []
        ssh.get_remote_server_key.side_effect = lambda: order.append('pin') or SimpleNamespace(asbytes=lambda: KEY)
        ssh.auth_password.side_effect = lambda *args, **kwargs: order.append('auth')
        module = SimpleNamespace(Transport=Mock(return_value=ssh))
        with patch.object(deco_tmp.importlib, 'import_module', return_value=module), \
                patch.object(deco_tmp.socket, 'create_connection', return_value=sock) as create:
            with client() as instance:
                self.assertEqual(order, ['pin', 'auth'])
                create.assert_called_once()
                self.assertEqual(create.call_args.args[0], ('router.example.test', 20001))
                ssh.auth_password.assert_called_once_with(USERNAME, PASSWORD, fallback=False)
                ssh.open_channel.assert_called_once()
                self.assertEqual(ssh.open_channel.call_args.args,
                                 ('direct-tcpip', ('127.0.0.1', 20002), ('127.0.0.1', 0)))
                self.assertEqual(instance._token, TOKEN)
                self.assertEqual(len(channel.sent), 1)
                self.assertEqual(sent_business(channel.sent[0])['opcode'], 1)
        self.assertTrue(channel.closed)
        ssh.close.assert_called_once()
        sock.close.assert_called_once()
        self.assertIsNone(instance._token)

    def test_pin_mismatch_prevents_authentication_and_closes_partial_resources(self):
        ssh, sock = Mock(), Mock()
        ssh.get_remote_server_key.return_value.asbytes.return_value = b'different-key'
        instance = client()
        with patch.object(deco_tmp.importlib, 'import_module', return_value=SimpleNamespace(Transport=lambda _: ssh)), \
                patch.object(deco_tmp.socket, 'create_connection', return_value=sock):
            with self.assertRaises(DecoTMPError) as raised:
                instance.open()
        self.assertEqual(raised.exception.error_type, 'HostKeyMismatch')
        ssh.auth_password.assert_not_called()
        ssh.open_channel.assert_not_called()
        ssh.close.assert_called_once()
        sock.close.assert_called_once()

    def test_openssh_and_hex_pins_have_identical_meaning(self):
        openssh = 'SHA256:' + base64.b64encode(hashlib.sha256(KEY).digest()).decode().rstrip('=')
        self.assertEqual(client(openssh)._host_key_pin, client(PIN.upper())._host_key_pin)

    def test_invalid_configuration_is_rejected_before_any_connection(self):
        cases = [
            {'host_key_sha256': None}, {'host_key_sha256': ''}, {'host_key_sha256': 'SHA256:not-a-pin'},
            {'username_sha1': 'admin'}, {'password': ''}, {'host': 'http://router'},
            {'timeout': 0}, {'timeout': float('inf')}, {'timeout': True},
        ]
        for override in cases:
            values = dict(host='router.example.test', username_sha1=USERNAME, password=PASSWORD, host_key_sha256=PIN)
            values.update(override)
            with self.subTest(override=override), patch.object(deco_tmp.socket, 'create_connection') as create:
                with self.assertRaises(ValueError):
                    DecoTMPTransport(**values)
                create.assert_not_called()

    def test_optional_dependency_failure_does_not_connect(self):
        with patch.object(deco_tmp.importlib, 'import_module', side_effect=ImportError('private detail')), \
                patch.object(deco_tmp.socket, 'create_connection') as create:
            with self.assertRaises(DecoTMPError) as raised:
                client().open()
        self.assertEqual(raised.exception.error_type, 'TMPDependencyUnavailable')
        self.assertNotIn('private detail', str(raised.exception))
        create.assert_not_called()

    def test_authentication_failure_is_one_attempt_and_sanitized(self):
        ssh, sock = Mock(), Mock()
        ssh.get_remote_server_key.return_value.asbytes.return_value = KEY
        ssh.auth_password.side_effect = RuntimeError(PASSWORD)
        with patch.object(deco_tmp.importlib, 'import_module', return_value=SimpleNamespace(Transport=lambda _: ssh)), \
                patch.object(deco_tmp.socket, 'create_connection', return_value=sock):
            with self.assertRaises(DecoTMPError) as raised:
                client().open()
        ssh.auth_password.assert_called_once_with(USERNAME, PASSWORD, fallback=False)
        ssh.open_channel.assert_not_called()
        ssh.close.assert_called_once()
        sock.close.assert_called_once()
        self.assertNotIn(PASSWORD, str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)

    def test_invalid_alloc_token_is_not_exposed(self):
        channel = Channel(peer_frame(1, 0, b'private-invalid-token'))
        ssh = Mock()
        ssh.get_remote_server_key.return_value.asbytes.return_value = KEY
        ssh.open_channel.return_value = channel
        with patch.object(deco_tmp.importlib, 'import_module', return_value=SimpleNamespace(Transport=lambda _: ssh)), \
                patch.object(deco_tmp.socket, 'create_connection', return_value=Mock()):
            with self.assertRaises(DecoTMPError) as raised:
                client().open()
        self.assertEqual(raised.exception.error_type, 'TMPInvalidSession')
        self.assertNotIn('private-invalid-token', str(raised.exception))
        self.assertTrue(channel.closed)

    def test_read_handles_partial_bytes_and_omits_params(self):
        response = {'error_code': 0, 'result': {'band2_4': {'guest': {'enable': True}}}}
        instance, channel = connected(json_response(response), chunk_size=1)
        with patch.object(deco_tmp.time, 'time', return_value=1700000000):
            result = instance.get_wlan()
        self.assertEqual(result, {'band2_4': {'guest': {'enable': True}}})
        request = sent_business(channel.sent[0])
        self.assertEqual(request['opcode'], 0x4009)
        self.assertEqual(json.loads(request['body']), {'config_version': 1700000000000})

    def test_guest_writes_have_exact_nested_single_band_payload(self):
        for wifi, band in ((Connection.GUEST_2G, 'band2_4'), (Connection.GUEST_5G, 'band5_1'),
                           (Connection.GUEST_6G, 'band6')):
            for enabled in (True, False):
                with self.subTest(wifi=wifi, enabled=enabled):
                    instance, channel = connected(json_response({'error_code': 0}, opcode=0x4008))
                    with patch.object(deco_tmp.time, 'time', return_value=1700000000):
                        self.assertEqual(instance.set_guest_wifi(wifi, enabled), {'error_code': 0})
                    self.assertEqual(len(channel.sent), 1)
                    packet = sent_business(channel.sent[0])
                    self.assertEqual(packet['opcode'], 0x4008)
                    self.assertEqual(json.loads(packet['body']), {
                        'config_version': 1700000000000, 'params': {band: {'guest': {'enable': enabled}}}})

    def test_non_guest_networks_and_non_boolean_enable_never_send(self):
        invalid = [(Connection.HOST_2G, True), (Connection.IOT_2G, True), ('GUEST_2G', True),
                   (Connection.GUEST_2G, 1), (Connection.GUEST_2G, 'on'), (Connection.GUEST_2G, None)]
        for wifi, enabled in invalid:
            instance, channel = connected()
            with self.subTest(wifi=wifi, enable=enabled), self.assertRaises(ValueError):
                instance.set_guest_wifi(wifi, enabled)
            self.assertEqual(channel.sent, [])

    def test_push_ack_requests_pull_without_replaying_write(self):
        incoming = peer_frame(0x4008, 0, packet_type=3) + json_response({'error_code': 0}, opcode=0x4008)
        instance, channel = connected(incoming)
        instance.set_guest_wifi(Connection.GUEST_2G, False)
        packets = [sent_business(frame) for frame in channel.sent]
        self.assertEqual([packet['type'] for packet in packets], [2, 4])
        self.assertEqual([packet['transaction'] for packet in packets], [0, 0])
        self.assertEqual([packet['opcode'] for packet in packets], [0x4008, 0x4008])
        self.assertEqual(packets[1]['body'], b'')

    def test_fragmented_response_reassembles_with_whole_body_crc(self):
        body = b'{"error_code":0,"result":{"value":true}}'
        checksum = zlib.crc32(body) & 0xFFFFFFFF
        fragments = [(0, body[:9]), (9, body[9:24]), (24, body[24:])]
        incoming = b''.join(peer_frame(0x4009, 0, fragment, total=len(body), offset=offset,
                                       body_checksum=checksum) for offset, fragment in fragments)
        instance, channel = connected(incoming, chunk_size=3)
        self.assertEqual(instance.get_wlan(), {'value': True})
        packets = [sent_business(frame) for frame in channel.sent]
        self.assertEqual([packet['type'] for packet in packets], [2, 4, 4])
        self.assertEqual([packet['offset'] for packet in packets], [0, 9, 24])

    def test_keepalive_and_unrelated_messages_are_bounded_and_skipped(self):
        incoming = (b'\x01\x01\x04\x00' + b'\x01\x01\x02\x00' +
                    peer_frame(0x4015, 0, b'notification', packet_type=2) +
                    peer_frame(0x4009, 99, b'stale') + json_response({'error_code': 0, 'result': {}}))
        instance, channel = connected(incoming)
        self.assertEqual(instance.get_wlan(), {})
        self.assertEqual(len(channel.sent), 2)
        self.assertEqual(channel.sent[1], b'\x01\x01\x04\x00')

    def test_bad_outer_crc_closes_session(self):
        incoming = bytearray(json_response({'error_code': 0}))
        incoming[-1] ^= 1
        instance, channel = connected(incoming)
        with self.assertRaises(DecoTMPError) as raised:
            instance.get_wlan()
        self.assertEqual(raised.exception.error_type, 'TMPFrameChecksumMismatch')
        self.assertTrue(channel.closed)

    def test_bad_business_crc_closes_session(self):
        instance, channel = connected(peer_frame(0x4009, 0, b'{}', body_checksum=1))
        with self.assertRaises(DecoTMPError) as raised:
            instance.get_wlan()
        self.assertEqual(raised.exception.error_type, 'TMPBodyChecksumMismatch')
        self.assertTrue(channel.closed)

    def test_invalid_fragment_offset_and_size_are_rejected(self):
        cases = [
            peer_frame(0x4009, 0, b'{}', offset=1),
            peer_frame(0x4009, 0, b'{}', total=1),
            peer_frame(0x4009, 0, b'', total=2),
            peer_frame(0x4009, 0, b'{}', total=1024 * 1024 + 1),
            peer_frame(0x4009, 0, b'{', total=2, body_checksum=1) +
            peer_frame(0x4009, 0, b'}', total=3, offset=1, body_checksum=1),
        ]
        for incoming in cases:
            instance, channel = connected(incoming)
            with self.subTest(incoming=incoming.hex()), self.assertRaises(DecoTMPError):
                instance.get_wlan()
            self.assertTrue(channel.closed)

    def test_invalid_transport_headers_fail_before_peer_payload_is_used(self):
        cases = [b'\x02\x01\x05\0', b'\x01\x01\x07\0', b'\x01\x01\x05\1']
        for incoming in cases:
            instance, channel = connected(incoming)
            with self.subTest(incoming=incoming.hex()), self.assertRaises(DecoTMPError) as raised:
                instance.get_wlan()
            self.assertEqual(raised.exception.error_type, 'TMPInvalidFrame')
            self.assertTrue(channel.closed)

    def test_eof_does_not_replay_an_ambiguous_write(self):
        instance, channel = connected(b'\x01\x01\x05\0')
        with self.assertRaises(DecoTMPError) as raised:
            instance.set_guest_wifi(Connection.GUEST_2G, False)
        self.assertEqual(raised.exception.error_type, 'TMPConnectionClosed')
        self.assertEqual(len(channel.sent), 1)
        self.assertTrue(channel.closed)

    def test_partial_send_failure_is_sanitized_without_retry(self):
        instance, channel = connected()
        channel.send_error = OSError(PASSWORD)
        with self.assertRaises(DecoTMPError) as raised:
            instance.set_guest_wifi(Connection.GUEST_2G, False)
        self.assertEqual(len(channel.sent), 1)
        self.assertEqual(raised.exception.error_type, 'TMPConnectionFailed')
        self.assertNotIn(PASSWORD, str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertTrue(channel.closed)

    def test_socket_timeout_is_not_retried(self):
        instance, channel = connected()
        channel.recv_error = socket.timeout(PASSWORD)
        with self.assertRaises(DecoTMPError) as raised:
            instance.get_wlan()
        self.assertEqual(raised.exception.error_type, 'TMPTimeout')
        self.assertEqual(len(channel.sent), 1)
        self.assertNotIn(PASSWORD, str(raised.exception))

    def test_one_monotonic_budget_bounds_the_request(self):
        instance, channel = connected()
        with patch.object(deco_tmp.time, 'monotonic', side_effect=[0, 0, 11]):
            with self.assertRaises(DecoTMPError) as raised:
                instance.get_wlan()
        self.assertEqual(raised.exception.error_type, 'TMPTimeout')
        self.assertTrue(channel.closed)

    def test_continuous_notifications_cannot_exceed_frame_budget(self):
        notification = peer_frame(0x4015, 0, b'notification', packet_type=2)
        instance, channel = connected(notification * 257)
        with self.assertRaises(DecoTMPError) as raised:
            instance.get_wlan()
        self.assertEqual(raised.exception.error_type, 'TMPFrameBudgetExceeded')
        self.assertEqual(len(channel.sent), 1)
        self.assertTrue(channel.closed)

    def test_explicit_business_rejection_is_distinguished_from_connection_failure(self):
        instance, channel = connected(peer_frame(0x4008, 0, packet_type=3, status=12))
        with self.assertRaises(DecoTMPRejected) as raised:
            instance.set_guest_wifi(Connection.GUEST_2G, False)
        self.assertEqual(raised.exception.code, 12)
        self.assertEqual(raised.exception.error_type, 'TMPRejected')
        self.assertEqual(len(channel.sent), 1)

    def test_unknown_business_packet_type_is_not_an_explicit_command_rejection(self):
        instance, channel = connected(peer_frame(0x4008, 0, packet_type=99, status=12))
        with self.assertRaises(DecoTMPError) as raised:
            instance.set_guest_wifi(Connection.GUEST_2G, False)
        self.assertNotIsInstance(raised.exception, DecoTMPRejected)
        self.assertEqual(raised.exception.error_type, 'TMPInvalidBusinessFrame')
        self.assertTrue(channel.closed)

    def test_explicit_json_rejection_does_not_expose_response_text(self):
        instance, channel = connected(json_response(
            {'error_code': -1002, 'message': PASSWORD}, opcode=0x4008))
        with self.assertRaises(DecoTMPRejected) as raised:
            instance.set_guest_wifi(Connection.GUEST_2G, False)
        self.assertEqual(raised.exception.code, -1002)
        self.assertNotIn(PASSWORD, str(raised.exception))
        self.assertEqual(len(channel.sent), 1)

    def test_invalid_json_shapes_close_connection_without_raw_text(self):
        cases = [b'not-json-' + PASSWORD.encode(), b'[]', b'\xff', b'{"error_code":false}',
                 b'{"error_code":0,"result":[]}', b'[' * 2000 + b'0' + b']' * 2000]
        for body in cases:
            instance, channel = connected(peer_frame(0x4009, 0, body))
            with self.subTest(body=body), self.assertRaises(DecoTMPError) as raised:
                instance.get_wlan()
            self.assertEqual(raised.exception.error_type, 'TMPInvalidJSON')
            self.assertNotIn(PASSWORD, str(raised.exception))
            self.assertTrue(channel.closed)

    def test_disconnected_operations_do_not_connect_or_send(self):
        instance = client()
        with patch.object(deco_tmp.socket, 'create_connection') as create:
            with self.assertRaises(DecoTMPError) as raised:
                instance.get_wlan()
        self.assertEqual(raised.exception.error_type, 'TMPNotConnected')
        create.assert_not_called()

    def test_identity_and_token_are_not_exposed_by_object_representation(self):
        instance = client()
        instance._token = TOKEN
        for private in (USERNAME, PASSWORD, TOKEN.decode()):
            self.assertNotIn(private, repr(instance))
        for forbidden in ('raw', 'discover', 'exec_command', 'invoke_shell'):
            self.assertFalse(hasattr(instance, forbidden))


if __name__ == '__main__':
    unittest.main()
