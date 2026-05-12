"""Unit tests for TplinkC20Router."""

from unittest.mock import MagicMock, patch
import pytest
from tplinkrouterc6u.client.c20 import TplinkC20Router


MOCK_LOGIN_REDIRECT_URL = "http://192.168.0.1/abc123def/userRpm/Index.htm"

MOCK_STATUS_HTML = """
<html>
<script>
var statusPara = new Array(
    "Archer C20", "0.9.1 4.0 v0044.0 Build 211201 Rel.12345n", "Archer C20 v5 00000000",
    "Connected", "1.2.3.4", "255.255.255.0", "1.2.3.1"
);
var wlanPara = new Array( "MySSID", "1", "6", "300Mbps" );
var wlan5gPara = new Array( "MySSID_5G", "1", "36", "867Mbps" );
</script>
</html>
"""

MOCK_DHCP_HTML = """
<html>
<script>
var DHCPDynList = new Array(
    "MyPhone", "AA:BB:CC:DD:EE:FF", "192.168.0.100", "02:00:00",
    "MyLaptop", "11:22:33:44:55:66", "192.168.0.101", "Permanent"
);
</script>
</html>
"""

MOCK_STATIC_HTML = """
<html>
<script>
var fixMapList = new Array(
    "AA:BB:CC:DD:EE:FF", "192.168.0.100", "MyPhone", "1",
    "11:22:33:44:55:66", "192.168.0.101", "MyLaptop", "1"
);
</script>
</html>
"""


@pytest.fixture
def router():
    return TplinkC20Router("http://192.168.0.1", "testpassword", "admin")


def _mock_response(text="", url="", status_code=200):
    r = MagicMock()
    r.text = text
    r.url = url
    r.status_code = status_code
    return r


class TestTplinkC20RouterAuth:
    def test_authorize_success(self, router):
        with patch.object(router._session, "post") as mock_post:
            mock_post.return_value = _mock_response(
                url=MOCK_LOGIN_REDIRECT_URL
            )
            router.authorize()
            assert router._stok == "abc123def"

    def test_authorize_fails_no_stok(self, router):
        with patch.object(router._session, "post") as mock_post:
            mock_post.return_value = _mock_response(url="http://192.168.0.1/")
            with pytest.raises(PermissionError, match="Login failed"):
                router.authorize()

    def test_authorize_connection_error(self, router):
        with patch.object(router._session, "post", side_effect=Exception("timeout")):
            with pytest.raises(ConnectionError, match="Login request failed"):
                router.authorize()

    def test_logout_clears_stok(self, router):
        router._stok = "abc123def"
        with patch.object(router._session, "get") as mock_get:
            mock_get.return_value = _mock_response()
            router.logout()
            assert router._stok == ""


class TestTplinkC20RouterFirmware:
    def test_get_firmware_from_js_array(self, router):
        router._stok = "abc123def"
        with patch.object(router._session, "get") as mock_get:
            mock_get.return_value = _mock_response(text=MOCK_STATUS_HTML)
            fw = router.get_firmware()
            assert "Build 211201" in fw.firmware_version
            assert "C20 v5" in fw.hardware_version

    def test_get_firmware_connection_error(self, router):
        router._stok = "abc123def"
        with patch.object(router._session, "get", side_effect=Exception("err")):
            with pytest.raises(ConnectionError, match="get_firmware failed"):
                router.get_firmware()


class TestTplinkC20RouterStatus:
    def test_get_status_wifi_enabled(self, router):
        router._stok = "abc123def"
        with patch.object(router._session, "get") as mock_get:
            mock_get.return_value = _mock_response(text=MOCK_STATUS_HTML)
            status = router.get_status()
            assert status.wifi_2g_enable is True
            assert status.wifi_5g_enable is True


class TestTplinkC20RouterDHCP:
    def test_get_ipv4_dhcp_leases(self, router):
        router._stok = "abc123def"
        with patch.object(router._session, "get") as mock_get:
            mock_get.return_value = _mock_response(text=MOCK_DHCP_HTML)
            leases = router.get_ipv4_dhcp_leases()
            assert len(leases) == 2
            assert leases[0].macaddr == "AA-BB-CC-DD-EE-FF"
            assert leases[0].ipaddr == "192.168.0.100"
            assert leases[1].hostname == "MyLaptop"

    def test_get_ipv4_reservations(self, router):
        router._stok = "abc123def"
        with patch.object(router._session, "get") as mock_get:
            mock_get.return_value = _mock_response(text=MOCK_STATIC_HTML)
            reservations = router.get_ipv4_reservations()
            assert len(reservations) == 2
            assert reservations[0].enabled is True
            assert reservations[1].ipaddr == "192.168.0.101"


class TestTplinkC20RouterHelpers:
    def test_extract_stok(self):
        url = "http://192.168.0.1/deadbeef01/userRpm/Index.htm"
        assert TplinkC20Router._extract_stok(url) == "deadbeef01"

    def test_extract_stok_no_match(self):
        assert TplinkC20Router._extract_stok("http://192.168.0.1/") == ""

    def test_parse_js_var(self):
        html = 'var myArr = new Array( "foo", "bar", "baz" );'
        result = TplinkC20Router._parse_js_var(html, "myArr")
        assert result == ["foo", "bar", "baz"]

    def test_parse_js_var_missing(self):
        result = TplinkC20Router._parse_js_var("<html></html>", "myArr")
        assert result == []