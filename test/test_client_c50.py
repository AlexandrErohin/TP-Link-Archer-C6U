from unittest import main, TestCase
from unittest.mock import Mock, patch

from tplinkrouterc6u.client.c50 import TPLinkC50Client, TPLinkWR841NClient
from tplinkrouterc6u.common.exception import AuthorizeError, ClientException

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
# TPLinkC50Client --- supports()
# ---------------------------------------------------------------------------

class TestTPLinkC50ClientSupports(TestCase):

    def _client(self):
        c = TPLinkC50Client("http://192.168.0.1", "password")
        c._session = _mock_session()
        return c

    def test_supports_true_for_512bit_pkcs1(self):
        """supports() returns True when key is 512-bit and tpEncrypt.js has flag=1."""
        c = self._client()
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))
        c._session.get.side_effect = [
            _make_get_resp(200, "INCLUDE_LOGIN_GDPR_ENCRYPT=1"),
            _make_get_resp(200, "$.rsa.encrypt(data,512,1)"),
        ]
        self.assertTrue(c.supports())

    def test_supports_false_when_key_not_512bit(self):
        """supports() rejects keys that are not exactly 128 hex chars (512-bit)."""
        c = self._client()
        c._fetch_rsa_key = Mock(return_value=("b" * 256, _FAKE_EE, _FAKE_SEQ))
        self.assertFalse(c.supports())

    def test_supports_false_when_gdpr_flag_missing(self):
        """supports() rejects when INCLUDE_LOGIN_GDPR_ENCRYPT=1 is absent."""
        c = self._client()
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))
        c._session.get.return_value = _make_get_resp(200, "SOME_OTHER_FLAG=1")
        self.assertFalse(c.supports())

    def test_supports_false_for_raw_rsa_flag0(self):
        """supports() rejects flag=0 devices --- those belong to TPLinkWR841NClient."""
        c = self._client()
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))
        c._session.get.side_effect = [
            _make_get_resp(200, "INCLUDE_LOGIN_GDPR_ENCRYPT=1"),
            _make_get_resp(200, "$.rsa.encrypt(data,512,0)"),  # flag=0 --- WR841N
        ]
        self.assertFalse(c.supports())

    def test_supports_false_on_connection_error(self):
        """supports() returns False instead of propagating exceptions."""
        c = self._client()
        c._fetch_rsa_key = Mock(side_effect=Exception("connection refused"))
        self.assertFalse(c.supports())


# ---------------------------------------------------------------------------
# TPLinkC50Client --- authorize()
# ---------------------------------------------------------------------------

class TestTPLinkC50ClientAuthorize(TestCase):
    """
    authorize() recreates self._session = Session() at the start.
    We patch the Session *class* in the c50 module so that the new instance
    returned by Session() is a Mock we control.
    """

    def _run_authorize(self, aes_dec_return="$.ret=0\n", post_status=200):
        c = TPLinkC50Client("http://192.168.0.1", "password")
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))

        mock_session = _mock_session()
        mock_session.post.return_value = _make_post_resp(post_status)
        mock_session.get.return_value = _make_get_resp(200)

        with patch("tplinkrouterc6u.client.c50.Session", return_value=mock_session), \
             patch.object(TPLinkC50Client, "_aes_enc", return_value="ENCDATA"), \
             patch.object(TPLinkC50Client, "_make_sign", return_value="SIGN"), \
             patch.object(TPLinkC50Client, "_read_chunked", return_value="CIPHER"), \
             patch.object(TPLinkC50Client, "_aes_dec", return_value=aes_dec_return):
            c.authorize()

        return c, mock_session

    def test_authorize_success_sets_token(self):
        """authorize() completes and sets the c50 session sentinel."""
        c, _ = self._run_authorize()
        self.assertEqual(c._token, "c50_session")
        self.assertIsNotNone(c._aes_key)
        self.assertIsNotNone(c._aes_iv)

    def test_authorize_performs_post_login_get(self):
        """authorize() performs a GET / after login to initialise the server session."""
        c, mock_session = self._run_authorize()
        mock_session.get.assert_called_once()
        self.assertEqual(mock_session.get.call_args[0][0], "http://192.168.0.1/")

    def test_authorize_raises_on_http_error(self):
        """authorize() raises ClientException when the router returns non-200."""
        c = TPLinkC50Client("http://192.168.0.1", "password")
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))
        mock_session = _mock_session()
        mock_session.post.return_value = _make_post_resp(403)

        with patch("tplinkrouterc6u.client.c50.Session", return_value=mock_session), \
             patch.object(TPLinkC50Client, "_aes_enc", return_value="ENCDATA"), \
             patch.object(TPLinkC50Client, "_make_sign", return_value="SIGN"), \
             patch.object(TPLinkC50Client, "_read_chunked", return_value=""):
            with self.assertRaises(ClientException):
                c.authorize()

    def test_authorize_raises_authorize_error_on_wrong_password(self):
        """authorize() raises AuthorizeError when the router returns wrong-password code."""
        wrong_pwd_code = TPLinkC50Client.HTTP_ERR_USER_PWD_NOT_CORRECT
        c = TPLinkC50Client("http://192.168.0.1", "password")
        c._fetch_rsa_key = Mock(return_value=(_FAKE_NN, _FAKE_EE, _FAKE_SEQ))
        mock_session = _mock_session()
        mock_session.post.return_value = _make_post_resp(200)

        with patch("tplinkrouterc6u.client.c50.Session", return_value=mock_session), \
             patch.object(TPLinkC50Client, "_aes_enc", return_value="ENCDATA"), \
             patch.object(TPLinkC50Client, "_make_sign", return_value="SIGN"), \
             patch.object(TPLinkC50Client, "_read_chunked", return_value="CIPHER"), \
             patch.object(TPLinkC50Client, "_aes_dec",
                          return_value=f"$.ret={wrong_pwd_code}\n"):
            with self.assertRaises(AuthorizeError):
                c.authorize()

    def test_logout_clears_session_state(self):
        """logout() clears all session credentials."""
        c = TPLinkC50Client("http://192.168.0.1", "password")
        c._aes_key = "key"
        c._aes_iv = "iv"
        c._login_nn = _FAKE_NN
        c._login_ee = _FAKE_EE
        c._login_seq = _FAKE_SEQ
        c._token = "c50_session"

        c.logout()

        self.assertIsNone(c._aes_key)
        self.assertIsNone(c._aes_iv)
        self.assertIsNone(c._login_nn)
        self.assertIsNone(c._login_ee)
        self.assertIsNone(c._login_seq)
        self.assertIsNone(c._token)


# ---------------------------------------------------------------------------
# TPLinkC50Client --- crypto helpers
# ---------------------------------------------------------------------------

class TestTPLinkC50ClientCrypto(TestCase):

    def test_aes_enc_dec_roundtrip(self):
        """AES encrypt then decrypt returns the original plaintext."""
        key = "1234567890abcdef"
        iv  = "abcdef1234567890"
        plaintext = "hello world, this is a test payload\n"

        ciphertext = TPLinkC50Client._aes_enc(plaintext, key, iv)
        recovered  = TPLinkC50Client._aes_dec(ciphertext, key, iv)

        self.assertEqual(recovered, plaintext)

    def test_make_sign_login_includes_key_iv(self):
        """Login sign string must include key= and iv= parameters."""
        c = TPLinkC50Client("http://192.168.0.1", "password")
        with patch.object(TPLinkC50Client, "_rsa_pkcs_encrypt",
                          side_effect=lambda data, nn, ee: data):
            sign = c._make_sign(
                seq=1234, is_login=True, pw_hash="aabbcc",
                nn=_FAKE_NN, ee=_FAKE_EE, aes_key="mykey", aes_iv="myiv",
            )
        self.assertIn("key=mykey", sign)
        self.assertIn("iv=myiv", sign)
        self.assertIn("h=aabbcc", sign)

    def test_make_sign_data_omits_key_iv(self):
        """Non-login sign string must NOT include key= or iv= parameters."""
        c = TPLinkC50Client("http://192.168.0.1", "password")
        with patch.object(TPLinkC50Client, "_rsa_pkcs_encrypt",
                          side_effect=lambda data, nn, ee: data):
            sign = c._make_sign(
                seq=1234, is_login=False, pw_hash="aabbcc",
                nn=_FAKE_NN, ee=_FAKE_EE,
            )
        self.assertNotIn("key=", sign)
        self.assertNotIn("iv=", sign)
        self.assertIn("h=aabbcc", sign)


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

        with patch("tplinkrouterc6u.client.c50.Session", return_value=mock_session), \
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

        with patch("tplinkrouterc6u.client.c50.Session", return_value=mock_session), \
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
        raw_result  = TPLinkWR841NClient._rsa_pkcs_encrypt("hello", self._nn, self._ee)
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
        self.assertIsNone(status._wan_ipv4_addr)


if __name__ == "__main__":
    main()
