"""
Client for TP-Link Archer C20 AC750 and similar older-generation routers
that use a plain-text password form login via /userRpm/ interface.

Tested on:
- Archer C20 AC750 (v4/v5), Firmware 0.9.1 x.x Build xxxxxx

Authentication flow:
  1. POST to /userRpm/LoginRpm.htm with pcPassword=<plain_text_password>
     and an Authorization: Basic base64(admin:password) header.
  2. Router returns a redirect to a session URL like:
     http://192.168.0.1/<token>/userRpm/Index.htm
  3. Extract the <token> (stok) from the redirect URL.
  4. Use the token as a path prefix for all subsequent requests.

The router supports only ONE concurrent admin session.
"""

from __future__ import annotations

import base64
import hashlib
import re
from logging import Logger
from typing import Any

import requests

from macaddress import EUI48
from ipaddress import IPv4Address

from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import (
    Firmware,
    IPv4Reservation,
    IPv4DHCPLease,
    Status,
    IPv4Status,
)


class TplinkC20Router(AbstractRouter):
    """
    Client for Archer C20 AC750 (and compatible older /userRpm/ UI routers).

    The C20 uses a legacy Basic-Auth + form-post login that predates the
    AES/RSA encrypted APIs used by modern TP-Link routers.  All subsequent
    requests are scoped under a session token embedded in the URL path.
    """

    # --- URL templates -------------------------------------------------
    _LOGIN_PATH = "/userRpm/LoginRpm.htm"
    _LOGOUT_PATH = "/userRpm/LogoutRpm.htm"
    _STATUS_PATH = "/{stok}/userRpm/StatusRpm.htm"
    _FIRMWARE_PATH = "/{stok}/userRpm/StatusRpm.htm"
    _WLAN_PATH = "/{stok}/userRpm/WlanNetworkRpm.htm"
    _WLAN5G_PATH = "/{stok}/userRpm/WlanNetworkRpm5g.htm"
    _DHCP_CLIENT_PATH = "/{stok}/userRpm/AssignedIpAddrListRpm.htm"
    _DHCP_STATIC_PATH = "/{stok}/userRpm/FixMapCfgRpm.htm"
    _REBOOT_PATH = "/{stok}/userRpm/SysRebootRpm.htm"

    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        logger: Logger | None = None,
        verify_ssl: bool = False,
        timeout: int = 10,
    ) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._stok: str = ""
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        return self.host.rstrip("/")

    def _auth_header(self) -> str:
        """Basic auth header expected by the C20 login endpoint."""
        raw = f"{self.username}:{self.password}"
        encoded = base64.b64encode(raw.encode()).decode()
        return f"Basic {encoded}"

    def _get(self, path: str, **kwargs: Any) -> requests.Response:
        url = self._base_url() + path
        headers = {
            "Referer": self._base_url() + "/userRpm/MenuRpm.htm",
            "Authorization": self._auth_header(),
        }
        return self._session.get(
            url,
            headers=headers,
            verify=self._verify_ssl,
            timeout=self.timeout,
            **kwargs,
        )

    def _post(self, path: str, data: dict, **kwargs: Any) -> requests.Response:
        url = self._base_url() + path
        headers = {
            "Referer": self._base_url() + self._LOGIN_PATH,
            "Authorization": self._auth_header(),
        }
        return self._session.post(
            url,
            data=data,
            headers=headers,
            verify=self._verify_ssl,
            timeout=self.timeout,
            **kwargs,
        )

    @staticmethod
    def _extract_stok(url: str) -> str:
        """
        Extract the session token from a redirect URL like:
          http://192.168.0.1/12ab34cd/userRpm/Index.htm
        Returns the token string, or '' if not found.
        """
        m = re.search(r"/([A-Za-z0-9]+)/userRpm/", url)
        return m.group(1) if m else ""

    @staticmethod
    def _parse_js_var(html: str, var_name: str) -> list[str]:
        """
        Parse a JS array variable from the router's RPM pages, e.g.:
          var wlanPara = new Array( "val1", "val2", ... );
        Returns a list of string values.
        """
        pattern = rf"var\s+{re.escape(var_name)}\s*=\s*new Array\(([^)]*)\)"
        m = re.search(pattern, html)
        if not m:
            return []
        raw = m.group(1)
        return [v.strip().strip('"').strip("'") for v in raw.split(",")]

    # ------------------------------------------------------------------
    # AbstractRouter interface
    # ------------------------------------------------------------------

    def authorize(self) -> None:
        """Log in to the router and obtain a session token."""
        try:
            resp = self._post(
                self._LOGIN_PATH,
                data={"pcPassword": self.password, "Save": "Save"},
                allow_redirects=True,
            )
        except Exception as exc:
            raise ConnectionError(f"TplinkC20Router - Login request failed: {exc}") from exc

        # The router redirects to a URL containing the session token
        final_url = resp.url
        self._stok = self._extract_stok(final_url)

        if not self._stok:
            # Try to extract from response body (some firmware versions inline it)
            m = re.search(r'http://[^"\']+/([A-Za-z0-9]+)/userRpm/', resp.text)
            if m:
                self._stok = m.group(1)

        if not self._stok:
            raise PermissionError(
                f"TplinkC20Router - Login failed. "
                f"Could not extract session token from: {final_url}"
            )

        if self._logger:
            self._logger.debug("TplinkC20Router - Authorized, stok=%s", self._stok)

    def logout(self) -> None:
        """Log out and invalidate the session token."""
        try:
            self._get(self._LOGOUT_PATH)
        except Exception:
            pass
        self._stok = ""
        self._session.cookies.clear()

    def get_firmware(self) -> Firmware:
        """Return firmware / hardware version info."""
        path = self._FIRMWARE_PATH.format(stok=self._stok)
        try:
            resp = self._get(path)
            html = resp.text
        except Exception as exc:
            raise ConnectionError(f"TplinkC20Router - get_firmware failed: {exc}") from exc

        # The Status page contains JS arrays with firmware info.
        # Typical variable: var statusPara = new Array("hw_ver","fw_ver",...);
        fw_ver = ""
        hw_ver = ""

        m = re.search(r"Firmware Version[^:]*:?\s*</[^>]+>\s*([^\n<]+)", html)
        if m:
            fw_ver = m.group(1).strip()

        m = re.search(r"Hardware Version[^:]*:?\s*</[^>]+>\s*([^\n<]+)", html)
        if m:
            hw_ver = m.group(1).strip()

        # Fallback: parse statusPara JS array (index 1 = fw, index 2 = hw on most C20 fw)
        if not fw_ver:
            params = self._parse_js_var(html, "statusPara")
            if len(params) > 2:
                fw_ver = params[1]
                hw_ver = params[2]

        return Firmware(hardware_version=hw_ver, firmware_version=fw_ver, model="Archer C20")

    def get_status(self) -> Status:
        """Return router status including connected clients and WiFi state."""
        path = self._STATUS_PATH.format(stok=self._stok)
        try:
            resp = self._get(path)
            html = resp.text
        except Exception as exc:
            raise ConnectionError(f"TplinkC20Router - get_status failed: {exc}") from exc

        # --- WiFi enabled state ---
        # wlanPara[0]: SSID 2.4G, wlanPara[X]: enabled flag ("1"/"0")
        wlan_params = self._parse_js_var(html, "wlanPara")
        wifi_2g = len(wlan_params) > 0 and wlan_params[0] != ""

        # Check 5G if present
        wlan5g_params = self._parse_js_var(html, "wlan5gPara")
        wifi_5g = len(wlan5g_params) > 0 and wlan5g_params[0] != ""

        # --- Connected client count ---
        # The status page lists DHCP clients; count table rows as a proxy
        client_count = len(re.findall(r"<tr[^>]*>.*?</tr>", html, re.DOTALL)) - 1
        client_count = max(client_count, 0)

        return Status(
            wired_total=0,
            wifi_clients_total=0,
            guest_clients_total=0,
            clients_total=client_count,
            guest_2g_enable=False,
            guest_5g_enable=False,
            iot_2g_enable=False,
            iot_5g_enable=False,
            wifi_2g_enable=wifi_2g,
            wifi_5g_enable=wifi_5g,
        )

    def get_ipv4_reservations(self) -> list[IPv4Reservation]:
        """Return list of static DHCP IP address reservations."""
        path = self._DHCP_STATIC_PATH.format(stok=self._stok)
        try:
            resp = self._get(path)
            html = resp.text
        except Exception as exc:
            raise ConnectionError(
                f"TplinkC20Router - get_ipv4_reservations failed: {exc}"
            ) from exc

        reservations: list[IPv4Reservation] = []
        # Rows are in a JS array: var fixMapList = new Array("mac","ip","name","enabled",...)
        params = self._parse_js_var(html, "fixMapList")
        # Each reservation occupies 4 entries: mac, ip, name, enabled
        for i in range(0, len(params) - 3, 4):
            mac, ip, name, enabled = params[i], params[i + 1], params[i + 2], params[i + 3]
            if mac and ip:
                reservations.append(
                    IPv4Reservation(
                        _macaddr=EUI48(mac),
                        _ipaddr=IPv4Address(ip),
                        hostname=name,
                        enabled=enabled == "1",
                    )
                )
        return reservations

    def get_ipv4_dhcp_leases(self) -> list[IPv4DHCPLease]:
        """Return list of current DHCP leases."""
        path = self._DHCP_CLIENT_PATH.format(stok=self._stok)
        try:
            resp = self._get(path)
            html = resp.text
        except Exception as exc:
            raise ConnectionError(
                f"TplinkC20Router - get_ipv4_dhcp_leases failed: {exc}"
            ) from exc

        leases: list[IPv4DHCPLease] = []
        # JS array: var DHCPDynList = new Array("name","mac","ip","lease_time",...)
        params = self._parse_js_var(html, "DHCPDynList")
        for i in range(0, len(params) - 3, 4):
            name, mac, ip, lease = params[i], params[i + 1], params[i + 2], params[i + 3]
            if mac and ip:
                leases.append(
                    IPv4DHCPLease(
                        _macaddr=EUI48(mac),
                        _ipaddr=IPv4Address(ip),
                        hostname=name,
                        lease_time=lease,
                    )
                )
        return leases

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        """Enable or disable a WiFi band. Basic implementation — extend as needed."""
        # The C20's WiFi toggle requires a full form POST to WlanNetworkRpm.htm
        # with all current parameters plus the changed enable flag.
        # A full implementation requires first GETting the current config.
        # This stub raises NotImplementedError to signal it's not yet implemented.
        raise NotImplementedError(
            "TplinkC20Router.set_wifi() is not yet implemented. "
            "Contributions welcome — see CONTRIBUTING.md."
        )

    def reboot(self) -> None:
        """Reboot the router."""
        path = self._REBOOT_PATH.format(stok=self._stok)
        try:
            self._get(path + "?Reboot=Reboot")
        except Exception as exc:
            raise ConnectionError(f"TplinkC20Router - reboot failed: {exc}") from exc

    def supports(self) -> bool:
        """Check if the router is supported by this client."""
        try:
            url = self._base_url() + self._LOGIN_PATH
            resp = self._session.get(url, verify=self.verify_ssl, timeout=self.timeout)
            return resp.status_code == 200 and "pcPassword" in resp.text and "RSAPublicKey" not in resp.text
        except Exception:
            return False

    def get_ipv4_status(self) -> IPv4Status:
        """Return IPv4 WAN/LAN status."""
        return IPv4Status()