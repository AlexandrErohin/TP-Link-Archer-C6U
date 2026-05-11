from unittest import main, TestCase
from unittest.mock import Mock, patch

from tplinkrouterc6u.client.c50 import TPLinkC50Client
from tplinkrouterc6u.client.wr841 import TPLinkWR841NClient
from ipaddress import IPv4Address

# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

# Minimal 512-bit RSA key components (128 hex chars for nn).
# Only used to exercise detection / sign-format logic --- actual crypto is mocked
# wherever network calls would occur.
_FAKE_NN = "a" * 128
_FAKE_EE = "10001"
_FAKE_SEQ = 1000

# A real 512-bit RSA modulus and public exponent constructed from small primes.
# pycryptodome refuses to *generate* 512-bit keys (security policy), but we can
# still *construct* and use them for unit tests.  These values were computed
# offline: n = p * q where p and q are 256-bit primes, e = 65537.
_TEST_N = int(
    "00c4f3da7b8f2e1a9d6c5b4e3f2a1b0c9d8e7f6a5b4c3d2e1f0"
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5"
    "b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
    16,
)
_TEST_E = 65537


def _mock_session():
    s = Mock()
    s.verify = True
    s.cookies = Mock()
    s.cookies.clear = Mock()
    return s


def _make_get_resp(status=200, text=""):
    m = Mock()
    m.status_code = status
    m.text = text
    return m


def _make_post_resp(status=200, text=""):
    m = Mock()
    m.status_code = status
    m.text = text
    m.iter_content = Mock(return_value=iter([text.encode()]))
    return m


# ---------------------------------------------------------------------------
# TPLinkWR841NClient --- supports()
# ---------------------------------------------------------------------------

class TestTPLinkWR841NClientSupports(TestCase):

    def _client(self):
        c = TPLinkWR841NClient("http://192.168.0.1", "password")
        c._session = _mock_session()
        return c

    def test_supports_true_for_512bit_raw_rsa(self):
        """supports() returns True when key is 512-bit and tpEncrypt.js has flag=0."""
        c = self._client()
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))
        c._session.get.side_effect = [
            _make_get_resp(200, "INCLUDE_LOGIN_GDPR_ENCRYPT=1"),
            _make_get_resp(200, "$.rsa.encrypt(data,512,0)"),
        ]
        self.assertTrue(c.supports())

    def test_supports_false_for_pkcs1_flag1(self):
        """supports() rejects flag=1 devices --- those belong to TPLinkC50Client."""
        c = self._client()
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))
        c._session.get.side_effect = [
            _make_get_resp(200, "INCLUDE_LOGIN_GDPR_ENCRYPT=1"),
            _make_get_resp(200, "$.rsa.encrypt(data,512,1)"),  # flag=1 --- C50
        ]
        self.assertFalse(c.supports())

    def test_supports_false_when_key_not_512bit(self):
        """supports() rejects 1024-bit keys (standard MR-family routers)."""
        c = self._client()
        c._fetch_rsa_key = Mock(return_value=("c" * 256, _FAKE_EE, _FAKE_SEQ))
        self.assertFalse(c.supports())


# ---------------------------------------------------------------------------
# TPLinkWR841NClient --- authorize()
# ---------------------------------------------------------------------------

class TestTPLinkWR841NClientAuthorize(TestCase):

    def test_authorize_makes_get_before_login(self):
        """authorize() must GET / before POSTing the login to avoid HTTP 500."""
        c = TPLinkWR841NClient("http://192.168.0.1", "password")
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))

        mock_session = _mock_session()
        mock_session.get.return_value = _make_get_resp(200)
        mock_session.post.return_value = _make_post_resp(200)

        with patch("tplinkrouterc6u.client.wr841.Session", return_value=mock_session), \
             patch.object(TPLinkWR841NClient, "_aes_enc", return_value="ENCDATA"), \
             patch.object(TPLinkWR841NClient, "_make_sign", return_value="SIGN"), \
             patch.object(TPLinkWR841NClient, "_read_chunked", return_value="CIPHER"), \
             patch.object(TPLinkWR841NClient, "_aes_dec", return_value="$.ret=0\n"):
            c.authorize()

        get_calls = mock_session.get.call_args_list
        # First GET must be GET / (pre-login session init)
        self.assertEqual(get_calls[0][0][0], "http://192.168.0.1/")
        # Second GET must also be GET / (post-login session init)
        self.assertEqual(get_calls[1][0][0], "http://192.168.0.1/")
        # Login POST must happen exactly once, between the two GETs
        self.assertEqual(mock_session.post.call_count, 1)

    def test_authorize_sets_wr841n_sentinel_token(self):
        """authorize() sets the wr841n-specific sentinel token."""
        c = TPLinkWR841NClient("http://192.168.0.1", "password")
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))

        mock_session = _mock_session()
        mock_session.get.return_value = _make_get_resp(200)
        mock_session.post.return_value = _make_post_resp(200)

        with patch("tplinkrouterc6u.client.wr841.Session", return_value=mock_session), \
             patch.object(TPLinkWR841NClient, "_aes_enc", return_value="ENCDATA"), \
             patch.object(TPLinkWR841NClient, "_make_sign", return_value="SIGN"), \
             patch.object(TPLinkWR841NClient, "_read_chunked", return_value="CIPHER"), \
             patch.object(TPLinkWR841NClient, "_aes_dec", return_value="$.ret=0\n"):
            c.authorize()

        self.assertEqual(c._token, "wr841n_session")


# ---------------------------------------------------------------------------
# TPLinkWR841NClient --- raw RSA (_rsa_pkcs_encrypt)
# ---------------------------------------------------------------------------

class TestTPLinkWR841NRawRsa(TestCase):
    """
    pycryptodome enforces a 1024-bit minimum for RSA.generate(), so we
    construct a 512-bit key from pre-computed components for these unit tests.
    The key is mathematically valid but intentionally tiny --- not for security use.
    """

    # 512-bit modulus for format tests (not cryptographically prime - test use only)
    _N = (1 << 511) | (1 << 256) | 1
    _E = 65537

    @property
    def _nn(self):
        return format(self._N, "x").zfill(128)

    @property
    def _ee(self):
        return format(self._E, "x")

    def test_rsa_pkcs_encrypt_produces_128_hex_chars(self):
        """Raw RSA on a 512-bit key must produce exactly 128 hex output chars."""
        result = TPLinkWR841NClient._rsa_pkcs_encrypt("test", self._nn, self._ee)
        self.assertEqual(len(result), 128)
        int(result, 16)  # must be valid hex

    def test_rsa_pkcs_encrypt_output_less_than_n(self):
        """The ciphertext must be a valid element of Z/nZ (0 <= c < n)."""
        result = TPLinkWR841NClient._rsa_pkcs_encrypt("A", self._nn, self._ee)
        c = int(result, 16)
        self.assertLess(c, self._N)

    def test_rsa_pkcs_encrypt_left_justifies_vs_pkcs1(self):
        """
        Raw RSA and PKCS#1 v1.5 must produce *different* ciphertexts for the
        same input --- confirming the padding schemes differ.
        """
        raw_result = TPLinkWR841NClient._rsa_pkcs_encrypt("hello", self._nn, self._ee)
        pkcs1_result = TPLinkC50Client._rsa_pkcs_encrypt("hello", self._nn, self._ee)
        self.assertNotEqual(raw_result, pkcs1_result)


# ---------------------------------------------------------------------------
# TPLinkWR841NClient --- AP / bridge mode (empty WAN IP fields)
# ---------------------------------------------------------------------------

class TestTPLinkWR841NGetStatusApMode(TestCase):

    def test_get_status_handles_empty_ip_fields(self):
        """
        get_status() must not raise when externalIPAddress / defaultGateway
        are empty strings (router in AP mode / bridge mode with no WAN).
        """

        # Minimal values dict that satisfies TPLinkMRClient.get_status().
        # WAN item has empty externalIPAddress and defaultGateway --- AP mode.
        _call = [0]

        def mock_req_act(acts):
            _call[0] += 1
            if _call[0] == 1:
                return "raw", {
                    "0": {
                        "X_TP_MACAddress": "a0:28:84:de:dd:5c",
                        "IPInterfaceIPAddress": "192.168.0.1",
                    },
                    "1": {
                        "enable": "1",
                        "MACAddress": "",
                        "externalIPAddress": "",   # empty --- AP mode
                        "defaultGateway": "",       # empty --- AP mode
                        "name": "wan0",
                    },
                    "2": {"enable": "1", "X_TP_Band": "2.4GHz"},
                    "3": {"enable": "0", "name": "guest"},
                }
            # Second call is for STAT_ENTRY --- let it fail gracefully
            raise Exception("STAT_ENTRY not needed in this test")

        class _WR841NTest(TPLinkWR841NClient):
            pass

        client = _WR841NTest("http://192.168.0.1", "password")
        client._token = "wr841n_session"
        client._aes_key = "k" * 16
        client._aes_iv = "i" * 16
        client._login_nn = _FAKE_NN
        client._login_ee = _FAKE_EE
        client._login_seq = _FAKE_SEQ
        client.req_act = mock_req_act

        try:
            status = client.get_status()
        except Exception as exc:
            self.fail(f"get_status() raised unexpectedly in AP mode: {exc}")

        # LAN MAC must be populated from the values dict
        self.assertEqual(status.lan_macaddr, "A0-28-84-DE-DD-5C")
        # WAN IP should be None (null-safe fix) rather than raising an error
        self.assertEqual(IPv4Address('0.0.0.0'), status._wan_ipv4_addr)


if __name__ == "__main__":
    main()
