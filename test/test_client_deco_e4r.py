from base64 import b64encode
from hashlib import md5
from json import dumps
from unittest import main, TestCase
from unittest.mock import patch
from urllib import parse
from ipaddress import IPv4Address
from macaddress import EUI48
from requests.exceptions import ConnectTimeout
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device
from tplinkrouterc6u import Connection, ClientException, ClientError
from tplinkrouterc6u.client.deco_e4r import TplinkDecoE4RRouter
from tplinkrouterc6u.provider import TplinkRouterProvider


# A synthetic RSA-512 public modulus (borrowed from the RE330 test fixtures) so the
# handshake's RSA operations succeed without touching a real device.
TEST_NN = ('BC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E'
           '9D3DE83FE70C2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3')
TEST_SEQ = '12345656'

# Synthetic challenge: 00007 header, a 32-char token key, then the alphabet blob.
CHALLENGE_LINE3 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
CHALLENGE_LINE4 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/'
CHALLENGE = ('00007\r\n00004\r\n00000\r\n{}\r\n{}\r\n00000\r\n'.format(CHALLENGE_LINE3, CHALLENGE_LINE4))


class ResponseMock:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


class SessionMock:
    """Stands in for requests.Session for the JSON data layer. Encrypts each
    fixture with the client's live AES cipher so the real decrypt path runs."""

    def __init__(self, client, fixtures):
        self._client = client
        self._fixtures = fixtures
        self.last_url = None
        self.last_body = None

    def post(self, url, data=None, headers=None, timeout=None, verify=None):
        self.last_url = url
        self.last_body = data
        for key, payload in self._fixtures.items():
            if key in url:
                return ResponseMock(self._client._encryption.aes_encrypt(payload))
        raise AssertionError('Unexpected data request URL: {}'.format(url))


class TplinkDecoE4RRouterTest(TplinkDecoE4RRouter):
    login_result = '00000\r\n'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sent = []

    def _code_request(self, query, data=None, use_token=False):
        self.sent.append((query, data, use_token))
        if query == 'code=7&asyn=1':
            return ResponseMock(CHALLENGE, 401)
        if query == 'code=16&asyn=0' and data == 'enable':
            return ResponseMock('00000')
        if query == 'code=16&asyn=0' and data == 'get':
            return ResponseMock('00000\r\n010001\r\n{}\r\n{}'.format(TEST_NN, TEST_SEQ))
        if query == 'code=7&asyn=0' and use_token:
            return ResponseMock(self.login_result)
        if query == 'code=16&asyn=0' and use_token:
            return ResponseMock('00000')
        if query == 'code=11&asyn=0':
            return ResponseMock('00000')
        raise ClientException('unexpected code request {}'.format(query))

    def use_fixtures(self, fixtures):
        self._session = SessionMock(self, fixtures)


def _device_list():
    return dumps({'error_code': 0, 'result': {'device_list': [
        {'role': 'master', 'device_model': 'E4R', 'hardware_ver': '4.0',
         'software_ver': '1.2.3 Build 20240101', 'mac': '00-00-00-00-00-01'},
        {'role': 'slave', 'device_model': 'E4R', 'hardware_ver': '4.0',
         'software_ver': '1.2.3 Build 20240101', 'mac': '00-00-00-00-00-02'},
    ]}})


def _client_list():
    return dumps({'error_code': 0, 'result': {'client_list': [
        {'mac': '00-00-00-00-00-11', 'ip': '10.0.0.11', 'name': b64encode(b'PHONE').decode(),
         'online': True, 'interface': 'main', 'connection_type': 'band2_4',
         'down_speed': 100, 'up_speed': 50, 'wire_type': 'wireless'},
        {'mac': '00-00-00-00-00-12', 'ip': '10.0.0.12', 'name': b64encode(b'LAPTOP').decode(),
         'online': True, 'wire_type': 'wired', 'down_speed': 0, 'up_speed': 0},
        {'mac': '00-00-00-00-00-13', 'ip': '10.0.0.13', 'name': b64encode(b'OFFLINE').decode(),
         'online': False, 'wire_type': 'wired'},
    ]}})


class TestTplinkDecoE4RRouter(TestCase):
    def test_security_encode_is_deterministic(self):
        client = TplinkDecoE4RRouterTest('', '')
        # (ord('A')^ord('x'))=57 -> 57%16=9 ; (ord('B')^ord('y'))=59 -> 59%16=11
        self.assertEqual(client._security_encode('AB', 'xy', '0123456789abcdef'), '9b')

    def test_authorize_sequence_and_token(self):
        client = TplinkDecoE4RRouterTest('', 'secretpwd')
        client.authorize()

        self.assertTrue(client._logged)
        self.assertEqual(client._ee, '010001')
        self.assertEqual(client._nn, TEST_NN)
        self.assertEqual(client._seq, TEST_SEQ)

        # Exact protocol order captured from the router's own login controller.
        order = [(q, d is not None and d.startswith('set '), t) if q == 'code=16&asyn=0' and t
                 else (q, d, t) for q, d, t in client.sent]
        self.assertEqual(order, [
            ('code=7&asyn=1', None, False),
            ('code=16&asyn=0', 'enable', False),
            ('code=16&asyn=0', 'get', False),
            ('code=7&asyn=0', client.sent[3][1], True),  # login body checked below
            ('code=16&asyn=0', True, True),              # set <RSA(aes)>
        ])

        # The id is securityEncode(line3, key=MD5(password), alphabet=line4).
        expected_token = parse.quote(
            client._security_encode(CHALLENGE_LINE3, md5(b'secretpwd').hexdigest(), CHALLENGE_LINE4),
            safe='!()*')
        self.assertEqual(client._token, expected_token)

        # The code=7 login body is exactly one RSA-512 block (128 hex chars).
        login_body = client.sent[3][1]
        self.assertEqual(len(login_body), 128)
        self.assertTrue(all(c in '0123456789abcdefABCDEF' for c in login_body))

    def test_authorize_raises_on_bad_password(self):
        client = TplinkDecoE4RRouterTest('', 'wrong')
        client.login_result = '00007\r\n00006\r\n'  # server rejects the login
        with self.assertRaises(ClientException):
            client.authorize()
        self.assertFalse(client._logged)

    def test_get_firmware(self):
        client = TplinkDecoE4RRouterTest('', 'pwd')
        client.authorize()
        client.use_fixtures({'form=device_list': _device_list()})

        firmware = client.get_firmware()
        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, '4.0')
        self.assertEqual(firmware.model, 'E4R')
        self.assertEqual(firmware.firmware_version, '1.2.3 Build 20240101')

    def test_get_status(self):
        client = TplinkDecoE4RRouterTest('', 'pwd')
        client.authorize()
        client.use_fixtures({
            'form=wan_ipv4': dumps({'error_code': 0, 'result': {
                'wan': {'dial_type': 'dynamic_ip',
                        'ip_info': {'mac': '00-00-00-00-00-0A', 'ip': '1.2.3.4', 'gateway': '1.2.3.1'}},
                'lan': {'ip_info': {'mac': '00-00-00-00-00-0B', 'ip': '192.168.0.1'}}}}),
            'form=performance': dumps({'error_code': 0, 'result': {'cpu_usage': 0.25, 'mem_usage': 0.5}}),
            'form=wlan': dumps({'error_code': 0, 'result': {
                'band2_4': {'host': {'enable': True}, 'guest': {'enable': False}},
                'band5_1': {'host': {'enable': True}, 'guest': {'enable': False}}}}),
            'form=client_list': _client_list(),
        })

        status = client.get_status()
        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_ipv4_addr, '1.2.3.4')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.0.1')
        self.assertEqual(status.wan_macaddr, '00-00-00-00-00-0A')
        self.assertEqual(status.cpu_usage, 0.25)
        self.assertEqual(status.mem_usage, 0.5)
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertFalse(status.guest_2g_enable)

        self.assertEqual(len(status.devices), 2)  # only online clients
        self.assertEqual(status.wired_total, 1)
        self.assertEqual(status.wifi_clients_total, 1)
        self.assertEqual(status.clients_total, 2)

        device = status.devices[0]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.HOST_2G)
        self.assertEqual(device.macaddr, '00-00-00-00-00-11')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '10.0.0.11')
        self.assertEqual(device.hostname, 'PHONE')
        self.assertEqual(device.down_speed, 100)
        self.assertEqual(device.up_speed, 50)

    def test_supports_true_and_false(self):
        client = TplinkDecoE4RRouterTest('', 'pwd')
        self.assertTrue(client.supports())

        bad = TplinkDecoE4RRouterTest('', 'pwd')
        bad.login_result = '00007\r\n00006\r\n'
        self.assertFalse(bad.supports())

    def test_supports_password_too_long(self):
        client = TplinkDecoE4RRouterTest('', 'a' * 54)
        self.assertFalse(client.supports())

    def test_authorize_password_too_long(self):
        client = TplinkDecoE4RRouterTest('', 'a' * 54)
        with self.assertRaises(ClientException):
            client.authorize()

    def test_request_retries_on_connect_timeout(self):
        client = TplinkDecoE4RRouterTest('', 'pwd')
        client.authorize()
        client.use_fixtures({'form=performance': dumps({'error_code': 0, 'result': {'cpu_usage': 0.1}})})

        attempts = {'count': 0}
        original_post = client._session.post

        def flaky_post(*args, **kwargs):
            attempts['count'] += 1
            if attempts['count'] < 3:
                raise ConnectTimeout('timeout')
            return original_post(*args, **kwargs)

        with patch.object(client._session, 'post', side_effect=flaky_post):
            result = client.request('admin/network?form=performance', dumps({'operation': 'read'}))

        self.assertEqual(attempts['count'], 3)
        self.assertEqual(result['cpu_usage'], 0.1)

    def test_request_error_includes_decrypted_body(self):
        client = TplinkDecoE4RRouterTest('', 'pwd')
        client.authorize()

        class _Session:
            def __init__(self, text):
                self._text = text

            def post(self, url, data=None, headers=None, timeout=None, verify=None):
                return ResponseMock(self._text)

        decrypted = 'dispatcher failure: attempt to index global mode'
        client._session = _Session(client._encryption.aes_encrypt(decrypted))

        with self.assertRaises(ClientError) as ctx:
            client.request('admin/network?form=performance', dumps({'operation': 'read'}))

        self.assertIn('Decrypted response', str(ctx.exception))
        self.assertIn('attempt to index global mode', str(ctx.exception))

    def test_logout(self):
        client = TplinkDecoE4RRouterTest('', 'pwd')
        client.authorize()
        client.logout()
        self.assertFalse(client._logged)
        self.assertEqual(client._token, '')
        self.assertIn(('code=11&asyn=0', None, True), client.sent)

    def test_registered_in_provider(self):
        clients = list(TplinkRouterProvider.get_clients())
        self.assertIn('TplinkDecoE4RRouter', clients)
        idx = clients.index('TplinkDecoE4RRouter')
        # Specific clients must be probed first so they are not shadowed by E4R.
        for specific in ('TPLinkDecoClient', 'TplinkC80Router', 'TplinkRE330Router'):
            self.assertLess(clients.index(specific), idx)
        # Must be probed before the clients known to over-eagerly accept.
        for greedy in ('TPLinkEAP115Client', 'TPLinkSG108EClient', 'TplinkC3200Router'):
            self.assertLess(idx, clients.index(greedy))


if __name__ == '__main__':
    main()
