from unittest import main, TestCase
from unittest.mock import patch, Mock

from tplinkrouterc6u import TplinkRouterAX72, TplinkRouterProvider
from test_client_c6u import TestTPLinkClient


class TestTPLinkClientAX72(TestTPLinkClient):
    """Inherits get_firmware/get_status/get_ipv4_status/etc.
    All other tests unchanged from TestTPLinkClient.

    TplinkRouterAX72 extends TplinkRouter directly, unlike TplinkRouterSG,
    which extends TplinkBaseRouter, so it inherits TplinkRouter's shortened
    URL scheme too. No path overrides are needed here.
    """

    router_class = TplinkRouterAX72


class TestTplinkRouterAX72Unit(TestCase):
    """Unit tests specific to TplinkRouterAX72's login signature and detection logic.

    authorize() itself, its 403-retry logic, and password encryption are all
    inherited unchanged from TplinkEncryption/TplinkRouter and are already
    covered by the base class's own tests. Only the pieces this class actually
    overrides are tested here.
    """

    def test_supports_password_too_long(self) -> None:
        long_password = 'a' * 126
        client = TplinkRouterAX72('http://192.168.0.1', long_password)
        self.assertFalse(client.supports())

    def test_get_login_data_omits_confirm(self) -> None:
        """The AX72 rejects a login body containing '&confirm=true'."""
        data = TplinkRouterAX72._get_login_data('deadbeef')

        self.assertEqual(data, 'operation=login&password=deadbeef')
        self.assertNotIn('confirm', data)

    def test_build_login_signature_real_key_size(self) -> None:
        """Regression test mirroring #171/#185's test_build_login_signature_real_key_size.

        Reuses the same real 512-bit auth key value already published in
        test_client_sg.py (public key material, so it is safe to reuse).
        Confirms this doesn't raise "Plaintext is too long."
        The naive flat 53-byte-per-block chunking, sized for PKCS1v1.5's
        11-byte overhead rather than OAEP's 42-byte overhead, does raise
        against a key this size.
        and produces a whole number of 512-bit (128 hex char) blocks.
        """
        client = TplinkRouterAX72('http://192.168.0.1', 'testpassword')
        client._encryption._key = b'1234567890123456'
        client._encryption._iv = b'6543210987654321'
        client.nn = (
            'ca8f1711cc27576fb0dae0d7df1b6a90465e8ea31ccf46b0004f4c60f6617df'
            '8fa147502e45353b4d3f8ad38cb9aee9a77d33973ce3d7d681bc2fb0ae242e631'
        )
        client.ee = '010001'

        sign = client._build_login_signature(seq_and_len=555111222, hash_value='a' * 64)

        self.assertGreater(len(sign), 0)
        self.assertEqual(len(sign) % 128, 0)
        self.assertTrue(
            all(len(sign[i:i + 128]) == 128 for i in range(0, len(sign), 128))
        )

    def test_prepare_data_hashes_with_sha256_not_md5(self) -> None:
        """The AX72 expects SHA256(username+password) instead of MD5."""
        client = TplinkRouterAX72('http://192.168.0.1', 'testpassword', username='admin')
        client._seq = '100'
        client.nn = (
            'ca8f1711cc27576fb0dae0d7df1b6a90465e8ea31ccf46b0004f4c60f6617df'
            '8fa147502e45353b4d3f8ad38cb9aee9a77d33973ce3d7d681bc2fb0ae242e631'
        )
        client.ee = '010001'

        with patch.object(client, '_build_login_signature', return_value='mock_sign') as mock_build_sig:
            client._prepare_data('operation=login&password=deadbeef')

        hash_value = mock_build_sig.call_args[0][1]
        self.assertEqual(len(hash_value), 64)  # SHA256 hex digest length; MD5 would be 32

        from hashlib import sha256, md5
        expected_sha256 = sha256(b'admintestpassword').hexdigest()
        unexpected_md5 = md5(b'admintestpassword').hexdigest()
        self.assertEqual(hash_value, expected_sha256)
        self.assertNotEqual(hash_value, unexpected_md5)

    @patch.object(TplinkRouterAX72, 'authorize')
    @patch.object(TplinkRouterAX72, 'logout')
    @patch.object(TplinkRouterAX72, '_request_pwd')
    @patch.object(TplinkRouterAX72, '_request_seq')
    def test_supports_true_for_512_bit_auth_key(
        self, mock_request_seq: Mock, mock_request_pwd: Mock, mock_logout: Mock, mock_authorize: Mock,
    ) -> None:
        """A 512-bit auth key (the AX72's actual size) should pass the pre-filter and attempt a real login."""
        client = TplinkRouterAX72('http://192.168.0.1', 'testpassword')

        def set_nn():
            client.nn = 'a' * 128  # 128 hex chars = 512 bits

        mock_request_seq.side_effect = set_nn

        self.assertTrue(client.supports())
        mock_authorize.assert_called_once()
        mock_logout.assert_called_once()

    @patch.object(TplinkRouterAX72, 'authorize')
    @patch.object(TplinkRouterAX72, '_request_pwd')
    @patch.object(TplinkRouterAX72, '_request_seq')
    def test_supports_false_for_non_512_bit_auth_key(
        self, mock_request_seq: Mock, mock_request_pwd: Mock, mock_authorize: Mock,
    ) -> None:
        """A differently-sized auth key should fail the cheap pre-filter without attempting a real login."""
        client = TplinkRouterAX72('http://192.168.0.1', 'testpassword')

        def set_nn():
            client.nn = 'a' * 256  # 1024-bit - a standard-scheme AX-series key size, not the AX72's

        mock_request_seq.side_effect = set_nn

        self.assertFalse(client.supports())
        mock_authorize.assert_not_called()

    def test_registered_in_provider(self) -> None:
        clients = list(TplinkRouterProvider.get_clients())
        self.assertIn('TplinkRouterAX72', clients)

        idx = clients.index('TplinkRouterAX72')
        self.assertLess(clients.index('TplinkRouterV1_11'), idx)
        self.assertLess(idx, clients.index('TplinkRouter'))


if __name__ == '__main__':
    main()
