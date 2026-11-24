"""Bounded WLAN access through the Deco app's local TMP-over-SSH transport."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import math
import re
import socket
import struct
import threading
import time
import zlib

from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.common.package_enum import Connection


_SSH_PORT = 20001
_TMP_TARGET = ('127.0.0.1', 20002)
_CRC_PLACEHOLDER = 0x5A6B7C8D
_MAX_RESPONSE = 1024 * 1024
_MAX_FRAMES = 256
_MAX_REQUEST = 8156
_GUEST_BANDS = {
    Connection.GUEST_2G: 'band2_4',
    Connection.GUEST_5G: 'band5_1',
    Connection.GUEST_6G: 'band6',
}


class DecoTMPError(ClientException):
    """A transport failure carrying no raw peer data or credential material."""

    def __init__(self, error_type: str, code: int | None = None) -> None:
        super().__init__('Deco TMP operation failed')
        self.error_type = error_type
        self.code = code


class DecoTMPRejected(DecoTMPError):
    """An explicit business or application rejection from the peer."""

    def __init__(self, code: int) -> None:
        super().__init__('TMPRejected', code)


def _decode_pin(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError('A SHA256 SSH host-key pin is required')
    if re.fullmatch(r'[0-9a-fA-F]{64}', value):
        return bytes.fromhex(value)
    if value.startswith('SHA256:'):
        encoded = value[7:]
        try:
            decoded = base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True)
        except (ValueError, TypeError):
            decoded = b''
        if len(decoded) == 32:
            return decoded
    raise ValueError('A SHA256 SSH host-key pin is required')


class DecoTMPTransport:
    """One authenticated local SSH channel, restricted to WLAN read/guest writes.

    The account username is an explicitly supplied SHA1 hex digest. Host identity
    is checked against a required SHA256 pin before password authentication.
    Commands and authentication attempts are never automatically replayed.
    """

    def __init__(self, host: str, username_sha1: str, password: str,
                 host_key_sha256: str, timeout: float = 10) -> None:
        if not isinstance(host, str) or not host or '/' in host or '@' in host:
            raise ValueError('A router hostname or IP address is required')
        if not isinstance(username_sha1, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', username_sha1):
            raise ValueError('An explicit SHA1 account username is required')
        if not isinstance(password, str) or not password:
            raise ValueError('An account password is required')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Timeout must be finite and positive')
        self._host = host
        self._username = username_sha1.lower()
        self._password = password
        self._host_key_pin = _decode_pin(host_key_sha256)
        self._timeout = float(timeout)
        self._socket = None
        self._transport = None
        self._channel = None
        self._token = None
        self._sequence = 1
        self._transaction = 0
        self._lock = threading.RLock()

    def __enter__(self) -> DecoTMPTransport:
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DecoTMPError('TMPTimeout')
        return remaining

    def open(self) -> None:
        """Authenticate once, open the fixed loopback channel, and allocate it."""
        with self._lock:
            if self._channel is not None:
                return
            try:
                paramiko = importlib.import_module('paramiko')
            except ImportError:
                raise DecoTMPError('TMPDependencyUnavailable') from None
            deadline = time.monotonic() + self._timeout
            try:
                self._socket = socket.create_connection(
                    (self._host, _SSH_PORT), timeout=self._remaining(deadline))
                self._transport = paramiko.Transport(self._socket)
                self._transport.banner_timeout = self._remaining(deadline)
                self._transport.start_client(timeout=self._remaining(deadline))
                key = self._transport.get_remote_server_key().asbytes()
                if not hmac.compare_digest(hashlib.sha256(key).digest(), self._host_key_pin):
                    raise DecoTMPError('HostKeyMismatch')
                self._transport.auth_timeout = self._remaining(deadline)
                self._transport.auth_password(self._username, self._password, fallback=False)
                self._channel = self._transport.open_channel(
                    'direct-tcpip', _TMP_TARGET, ('127.0.0.1', 0),
                    timeout=self._remaining(deadline))
                self._sequence = 1
                self._transaction = 0
                token = self._request(0x0001, b'', deadline)
                if not re.fullmatch(b'[0-9a-fA-F]{32}', token):
                    raise DecoTMPError('TMPInvalidSession')
                self._token = token
            except DecoTMPError:
                self.close()
                raise
            except Exception:
                self.close()
                raise DecoTMPError('SSHConnectionFailed') from None

    def close(self) -> None:
        """Release all local connection resources, including partially opened ones."""
        with self._lock:
            for resource in (self._channel, self._transport, self._socket):
                try:
                    if resource is not None:
                        resource.close()
                except Exception:
                    pass
            self._channel = self._transport = self._socket = None
            self._token = None

    @staticmethod
    def _business(opcode: int, packet_type: int, transaction: int,
                  body: bytes = b'', offset: int = 0) -> bytes:
        return struct.pack('>BBHBBHIII', 1, 2, opcode, packet_type, 0, transaction,
                           zlib.crc32(body) & 0xFFFFFFFF, len(body), offset) + body

    @staticmethod
    def _frame(payload: bytes, sequence: int) -> bytes:
        header = struct.pack('>BBBBHBBI', 1, 1, 5, 0, len(payload), 0, 0, sequence)
        checksum = zlib.crc32(header + struct.pack('>I', _CRC_PLACEHOLDER) + payload) & 0xFFFFFFFF
        return header + struct.pack('>I', checksum) + payload

    def _send(self, packet: bytes, deadline: float) -> None:
        self._channel.settimeout(self._remaining(deadline))
        self._channel.sendall(self._frame(packet, self._sequence))
        self._sequence = 1 if self._sequence == 0xFFFFFFFF else self._sequence + 1

    def _receive_exact(self, size: int, deadline: float) -> bytes:
        result = bytearray()
        while len(result) < size:
            self._channel.settimeout(self._remaining(deadline))
            part = self._channel.recv(size - len(result))
            if not part:
                raise DecoTMPError('TMPConnectionClosed')
            result.extend(part)
        return bytes(result)

    def _receive_frame(self, deadline: float) -> bytes | None:
        head = self._receive_exact(4, deadline)
        if head[:2] != b'\x01\x01':
            raise DecoTMPError('TMPInvalidFrame')
        if head[2] == 4 and head[3] == 0:
            self._channel.settimeout(self._remaining(deadline))
            self._channel.sendall(head)
            return None
        if head[2] == 2 and head[3] == 0:
            return None
        if head[2] == 6:
            raise DecoTMPError('TMPTransportRejected', head[3])
        if head[2] != 5 or head[3] != 0:
            raise DecoTMPError('TMPInvalidFrame')
        header = head + self._receive_exact(12, deadline)
        length, subtype, status, _, checksum = struct.unpack_from('>HBBII', header, 4)
        if subtype != 0 or status != 0:
            raise DecoTMPError('TMPInvalidFrame')
        payload = self._receive_exact(length, deadline)
        expected = zlib.crc32(header[:12] + struct.pack('>I', _CRC_PLACEHOLDER) + payload) & 0xFFFFFFFF
        if checksum != expected:
            raise DecoTMPError('TMPFrameChecksumMismatch')
        return payload

    def _request(self, opcode: int, body: bytes, deadline: float | None = None) -> bytes:
        with self._lock:
            if self._channel is None:
                raise DecoTMPError('TMPNotConnected')
            if len(body) > _MAX_REQUEST:
                raise DecoTMPError('TMPRequestTooLarge')
            if deadline is None:
                deadline = time.monotonic() + self._timeout
            transaction = self._transaction
            self._transaction = (transaction + 1) & 0xFFFF
            try:
                self._send(self._business(opcode, 2, transaction, body), deadline)
                result = bytearray()
                total = checksum = None
                pulled = False
                for _ in range(_MAX_FRAMES):
                    payload = self._receive_frame(deadline)
                    if payload is None:
                        continue
                    if len(payload) < 20:
                        raise DecoTMPError('TMPInvalidBusinessFrame')
                    major, minor, response_op, packet_type, status, response_tx, crc, size, offset = (
                        struct.unpack_from('>BBHBBHIII', payload))
                    if (major, minor) != (1, 2):
                        raise DecoTMPError('TMPInvalidBusinessFrame')
                    if response_tx != transaction or response_op != opcode or packet_type == 2:
                        continue
                    if packet_type not in (3, 5):
                        raise DecoTMPError('TMPInvalidBusinessFrame')
                    if status != 0:
                        raise DecoTMPRejected(status)
                    if packet_type == 3:
                        if not pulled:
                            self._send(self._business(opcode, 4, transaction, offset=len(result)), deadline)
                            pulled = True
                        continue
                    if size > _MAX_RESPONSE:
                        raise DecoTMPError('TMPResponseTooLarge')
                    if total is None:
                        total, checksum = size, crc
                    if size != total or crc != checksum or offset != len(result):
                        raise DecoTMPError('TMPInvalidFragment')
                    fragment = payload[20:]
                    if len(result) + len(fragment) > total:
                        raise DecoTMPError('TMPInvalidFragment')
                    result.extend(fragment)
                    if len(result) == total:
                        if zlib.crc32(result) & 0xFFFFFFFF != checksum:
                            raise DecoTMPError('TMPBodyChecksumMismatch')
                        return bytes(result)
                    if not fragment:
                        raise DecoTMPError('TMPInvalidFragment')
                    self._send(self._business(opcode, 4, transaction, offset=len(result)), deadline)
                    pulled = True
                raise DecoTMPError('TMPFrameBudgetExceeded')
            except DecoTMPRejected:
                raise
            except DecoTMPError:
                self.close()
                raise
            except (socket.timeout, TimeoutError):
                self.close()
                raise DecoTMPError('TMPTimeout') from None
            except Exception:
                self.close()
                raise DecoTMPError('TMPConnectionFailed') from None

    def _json_call(self, opcode: int, params: dict | None = None) -> dict:
        envelope = {'config_version': int(time.time() * 1000)}
        if params is not None:
            envelope['params'] = params
        body = json.dumps(envelope, separators=(',', ':')).encode('utf-8')
        raw = self._request(opcode, body)
        try:
            document = json.loads(raw.decode('utf-8'))
            if not isinstance(document, dict):
                raise ValueError
            code = document.get('error_code')
            if code is not None and type(code) is not int:
                raise ValueError
        except (UnicodeError, ValueError, RecursionError):
            self.close()
            raise DecoTMPError('TMPInvalidJSON') from None
        if code is not None and code != 0:
            raise DecoTMPRejected(code)
        result = document.get('result', document)
        if not isinstance(result, dict):
            self.close()
            raise DecoTMPError('TMPInvalidJSON')
        return result

    def get_wlan(self) -> dict:
        """Read WLAN data; callers must keep any returned network secrets private."""
        return self._json_call(0x4009)

    def set_guest_wifi(self, wifi: Connection, enable: bool) -> dict:
        """Send one minimal guest-band enable command; its ACK is not readback."""
        if not isinstance(wifi, Connection) or wifi not in _GUEST_BANDS:
            raise ValueError('Only Deco guest Wi-Fi bands are supported')
        if type(enable) is not bool:
            raise ValueError('Wi-Fi enable must be a boolean')
        return self._json_call(0x4008, {_GUEST_BANDS[wifi]: {'guest': {'enable': enable}}})
