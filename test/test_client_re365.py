"""Unit tests for the TP-Link RE365 client.

All HTTP calls are mocked; no physical RE365 or network access is required.
Run from the repository root with:
    python -m unittest discover -s test -p test_client_re365.py -v
"""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from requests.exceptions import HTTPError

from tplinkrouterc6u.client.re365 import (
    TplinkRE365Router,
    devices_from_wireless_grid,
)
from tplinkrouterc6u.common.exception import AuthorizeError, ClientException


class TestRE365Client(unittest.TestCase):
    """Exercise the RE365 protocol and presence-data mapping in isolation."""

    def setUp(self):
        self.router = TplinkRE365Router("http://192.0.2.1", "test-password")

    def tearDown(self):
        # Do not call logout(): these tests have no real network session.
        self.router._session.close()

    def read_status(self, wifi_data):
        """Mock the Wi-Fi and LAN status endpoints in their expected order."""
        lan_data = {"lan_macaddr": "AA:BB:CC:DD:EE:FF"}
        with (
            patch.object(self.router, "authorize") as authorize,
            patch.object(
                self.router, "_read_data", side_effect=[wifi_data, lan_data]
            ) as read,
        ):
            status = self.router.get_status()
        authorize.assert_called_once_with()
        self.assertEqual(
            read.call_args_list,
            [call("status.json"), call("status_lan_ipv4.json")],
        )
        return status

    def test_post_invalid_json(self):
        response = Mock()
        response.json.side_effect = ValueError("Invalid JSON")
        with patch.object(self.router._session, "post", return_value=response):
            with self.assertRaisesRegex(ClientException, "invalid JSON"):
                self.router._post("status.json", {"operation": "read"})

    def test_post_login_failed(self):
        response = Mock()
        response.json.return_value = {
            "success": False,
            "timeout": False,
            "errorcode": 123,
        }
        with patch.object(self.router._session, "post", return_value=response):
            with self.assertRaises(AuthorizeError):
                self.router._post("login.json", {"operation": "login"})

    def test_read_data_missing_data(self):
        with patch.object(self.router, "_post", return_value={
            "success": True,
            "timeout": False,
        }):
            with self.assertRaisesRegex(ClientException, "missing or invalid data"):
                self.router._read_data("status.json")

    def test_get_status_with_clients(self):
        status = self.read_status({
            "wirelessCount": 2,
            "wirelessGrid": [
                {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.0.10", "name": "Pixel"},
                {"mac": "AA:BB:CC:00:00:02", "ipaddr": "192.168.0.11", "name": "iPhone"},
            ],
            "wireless_2g_enable": "on",
            "wireless_5g_enable": "off",
        })
        self.assertEqual(status.clients_total, 2)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(
            {d.macaddr.lower() for d in status.devices},
            {"aa-bb-cc-00-00-01", "aa-bb-cc-00-00-02"},
        )
        self.assertEqual({d.hostname for d in status.devices}, {"Pixel", "iPhone"})
        self.assertEqual(status.lan_macaddr.lower(), "aa-bb-cc-dd-ee-ff")
        self.assertIs(status.wifi_2g_enable, True)
        self.assertIs(status.wifi_5g_enable, False)

    def test_get_status_empty_grid(self):
        status = self.read_status({"wirelessCount": 0, "wirelessGrid": []})
        self.assertEqual(status.devices, [])
        self.assertEqual(status.wifi_clients_total, 0)
        self.assertEqual(status.clients_total, 0)

    def test_get_status_missing_grid(self):
        with (
            patch.object(self.router, "authorize"),
            patch.object(self.router, "_read_data", return_value={"wirelessCount": 2}),
            self.assertRaisesRegex(ClientException, "wirelessGrid"),
        ):
            self.router.get_status()

    def test_get_status_api_error(self):
        with (
            patch.object(self.router, "authorize"),
            patch.object(
                self.router, "_read_data", side_effect=ClientException("API error")
            ),
            self.assertRaisesRegex(ClientException, "API error"),
        ):
            self.router.get_status()

    def test_get_status_lan_error(self):
        wifi_data = {
            "wirelessCount": 1,
            "wirelessGrid": [
                {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.0.10", "name": "Pixel"}
            ],
        }
        with (
            patch.object(self.router, "authorize"),
            patch.object(
                self.router, "_read_data",
                side_effect=[wifi_data, ClientException("LAN error")]
            ),
            self.assertRaisesRegex(ClientException, "LAN error"),
        ):
            self.router.get_status()

    def test_get_status_rejects_invalid_macs(self):
        with self.assertRaises(ClientException):
            self.read_status({
                "wirelessCount": 1,
                "wirelessGrid": [
                    {"mac": "invalid", "ip": "192.168.0.10", "name": "Phone"}
                ],
            })

    def test_get_status_partial_invalid_grid(self):
        wifi_data = {
            "wirelessCount": 3,
            "wirelessGrid": [
                {"mac": "AA:BB:CC:00:00:01", "name": "Pixel", "ip": "192.168.0.10"},
                {"mac": "INVALID", "name": "iPhone", "ip": "192.168.0.11"},
                {"mac": "AA:BB:CC:00:00:03", "name": "PC", "ip": "192.168.0.12"},
            ],
        }
        with (
            patch.object(self.router, "authorize"),
            patch.object(
                self.router, "_read_data",
                side_effect=[wifi_data, {"lan_macaddr": "AA:BB:CC:DD:EE:FF"}]
            ),
            self.assertRaises(ClientException),
        ):
            self.router.get_status()

    def test_get_status_inconsistent_wireless_count(self):
        with (
            patch.object(self.router, "authorize"),
            patch.object(self.router, "_read_data", return_value={
                "wirelessCount": 3,
                "wirelessGrid": [],
            }),
            self.assertRaisesRegex(ClientException, "wirelessCount"),
        ):
            self.router.get_status()

    def _fake_get_with_cookie(self, *args, **kwargs):
        self.router._session.cookies.set("COOKIE", "test-nonce")
        return Mock()

    def test_authorize_success(self):
        with (
            patch.object(self.router._session, "get", side_effect=self._fake_get_with_cookie),
            patch.object(self.router, "_post") as post,
        ):
            self.router.authorize()
        self.assertIs(self.router._authorized, True)
        post.assert_called_once()
        resource, data = post.call_args.args
        self.assertEqual(resource, "login.json")
        self.assertEqual(data["operation"], "login")
        self.assertEqual(data["nonce"], "test-nonce")
        self.assertEqual(data["encoded"], "7DD72451E4F61A8C4FC44EA3816A511D")

    def test_authorize_missing_cookie(self):
        with patch.object(self.router._session, "get", return_value=Mock()):
            with self.assertRaisesRegex(ClientException, "COOKIE missing"):
                self.router.authorize()
        self.assertIs(self.router._authorized, False)

    def test_authorize_login_rejected(self):
        with (
            patch.object(self.router._session, "get", side_effect=self._fake_get_with_cookie),
            patch.object(
                self.router, "_post", side_effect=AuthorizeError("Login rejected")
            ),
            self.assertRaises(AuthorizeError),
        ):
            self.router.authorize()
        self.assertIs(self.router._authorized, False)
        self.assertFalse(self.router._session.cookies)

    def _assert_supports(self, model, expected):
        with (
            patch.object(self.router, "authorize") as authorize,
            patch.object(self.router, "get_firmware",
                         return_value=SimpleNamespace(model=model)),
            patch.object(self.router, "logout") as logout,
        ):
            self.assertIs(self.router.supports(), expected)
        authorize.assert_called_once_with()
        if expected:
            logout.assert_not_called()
        else:
            logout.assert_called_once_with()

    def test_supports_re365(self):
        self._assert_supports("RE365", True)

    def test_supports_other_model(self):
        self._assert_supports("RE305", False)

    def test_supports_firmware_error(self):
        with (
            patch.object(self.router, "authorize"),
            patch.object(self.router, "get_firmware",
                         side_effect=ClientException("Firmware error")),
            patch.object(self.router, "logout") as logout,
        ):
            self.assertIs(self.router.supports(), False)
        logout.assert_called_once_with()

    def test_get_firmware(self):
        with (
            patch.object(self.router, "authorize"),
            patch.object(self.router, "_read_data", return_value={
                "model": "RE365",
                "hardware_version": "RE365 v1.0",
                "firmware_version": "1.0.4",
            }),
        ):
            firmware = self.router.get_firmware()
        self.assertEqual(firmware.model, "RE365")
        self.assertEqual(firmware.hardware_version, "RE365 v1.0")
        self.assertEqual(firmware.firmware_version, "1.0.4")

    def test_logout_clears_session_on_http_error(self):
        self.router._authorized = True
        self.router._session.cookies.set("COOKIE", "test-nonce")
        response = Mock()
        response.raise_for_status.side_effect = HTTPError("HTTP 500")
        with (
            patch.object(self.router._session, "post", return_value=response),
            self.assertRaises(HTTPError),
        ):
            self.router.logout()
        self.assertIs(self.router._authorized, False)
        self.assertFalse(self.router._session.cookies)

    def _assert_post_error(self, payload, error):
        response = Mock()
        response.json.return_value = payload
        with (
            patch.object(self.router._session, "post", return_value=response),
            self.assertRaisesRegex(ClientException, error),
        ):
            self.router._post("status.json", {"operation": "read"})

    def test_post_unexpected_response_format(self):
        self._assert_post_error([], "unexpected response format")

    def test_post_device_reported_timeout(self):
        self._assert_post_error({"success": True, "timeout": True},
                                "device reported timeout")

    def test_post_api_error(self):
        self._assert_post_error({"success": False, "errorcode": 123}, "API error")

    def _assert_invalid_wireless_entry(self, entry):
        with self.assertRaises(ClientException):
            devices_from_wireless_grid([entry])

    def test_wireless_grid_none_entry(self):
        self._assert_invalid_wireless_entry(None)

    def test_wireless_grid_missing_mac(self):
        self._assert_invalid_wireless_entry({})

    def test_wireless_grid_invalid_mac(self):
        self._assert_invalid_wireless_entry({"mac": "INVALID"})

    def test_wireless_grid_zero_mac(self):
        self._assert_invalid_wireless_entry({"mac": "00:00:00:00:00:00"})

    def test_wireless_grid_duplicate_mac(self):
        grid = [
            {"mac": "AA:BB:CC:00:00:01", "name": "Pixel", "ip": "192.168.0.10"},
            {"mac": "AA:BB:CC:00:00:01", "name": "Pixel", "ip": "192.168.0.10"},
        ]
        self.assertEqual(len(devices_from_wireless_grid(grid)), 1)

    def test_wireless_grid_unknown_hostname(self):
        devices = devices_from_wireless_grid([{
            "mac": "AA:BB:CC:00:00:01",
            "name": "UNKNOWN",
            "ip": "192.168.0.10",
        }])
        self.assertEqual(devices[0].hostname, devices[0].macaddr)


if __name__ == "__main__":
    unittest.main()
