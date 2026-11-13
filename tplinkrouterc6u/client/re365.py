"""TP-Link RE365 client implementation for tplinkrouterc6u.

Implements the RE365 web interface's cookie-based authentication, active Wi-Fi
client discovery, LAN MAC retrieval, and firmware information. Management
operations that have not been implemented are explicitly unsupported.
"""
from __future__ import annotations

from hashlib import md5
from logging import Logger

from requests import Session
from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.dataclass import Device, Firmware, Status
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.exception import (
    AuthorizeError,
    ClientException,
)


def _md5_upper(text: str) -> str:
    """Return the uppercase hexadecimal MD5 digest expected by the RE365 API."""
    return md5(text.encode("utf-8")).hexdigest().upper()


def _login_hash(password: str, nonce: str) -> str:
    """Reproduce the RE365 login hash: MD5(MD5(password) + ':' + nonce)."""
    return _md5_upper(f"{_md5_upper(password)}:{nonce}")


def devices_from_wireless_grid(grid: list[dict]) -> list[Device]:
    """Convert the active Wi-Fi client list into Device objects.

    Reject malformed entries rather than silently dropping clients: an
    incomplete list could be mistaken for devices leaving the network.
    Duplicate MAC addresses are collapsed into a single device.
    """
    result: list[Device] = []
    seen: set[str] = set()
    for item in grid:
        if not isinstance(item, dict):
            raise ClientException("RE365: invalid client entry")

        mac = str(item.get("mac") or "").strip()

        if not mac:
            raise ClientException("RE365: client MAC missing")

        try:
            addr = get_mac(mac)
        except Exception as exc:
            raise ClientException(
                f"RE365: invalid client MAC: {mac}"
            ) from exc

        if addr == get_mac("00:00:00:00:00:00"):
            raise ClientException("RE365: null client MAC")

        normalized = str(addr)
        # A MAC address is the stable identity used by presence tracking.
        if normalized in seen:
            continue
        seen.add(normalized)
        name = str(item.get("name") or "").strip()
        if not name or name.upper() == "UNKNOWN":
            name = normalized

        result.append(Device(
            type=Connection.UNKNOWN,
            _macaddr=addr,
            _ipaddr=get_ip(item.get("ip") or item.get("ipaddr") or ""),
            hostname=name,
        ))
    return result


class TplinkRE365Router(AbstractRouter):
    """Access the RE365 web API for device tracking and basic device identity.

    The client supports authentication, status polling, firmware information,
    and logout. Router management operations are not implemented.
    """

    def __init__(self, host: str, password: str, username: str = "admin",
                 logger: Logger | None = None, verify_ssl: bool = True,
                 timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self.host = self.host.rstrip("/")
        # Reuse one HTTP session to retain the authentication cookie across calls.
        self._session = Session()
        self._session.verify = verify_ssl
        self._session.headers.update({
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.host}/webpages/",
            "User-Agent": "Mozilla/5.0 (tplinkrouterc6u RE365 experimental)",
        })
        self._authorized = False

    def _post(self, resource: str, data: dict) -> dict:
        """POST form data and validate the RE365 API response envelope.

        Transport/HTTP failures propagate as requests exceptions. Invalid JSON
        and API-level errors raise library exceptions; they must not be treated
        as an empty list of connected clients.
        """
        url = f"{self.host}/webpages/data/{resource}"

        response = self._session.post(
            url,
            data=data,
            timeout=self.timeout,
        )

        response.raise_for_status()

        # An HTTP 200 response may still contain invalid JSON or an API error.
        try:
            result = response.json()
        except ValueError as exc:
            raise ClientException(
                f"RE365 {resource}: invalid JSON response"
            ) from exc

        if not isinstance(result, dict):
            raise ClientException(
                f"RE365 {resource}: unexpected response format"
            )

        # 'timeout' and 'success' are fields in the RE365 response, not HTTP codes.
        if result.get("timeout") is True:
            raise ClientException(
                f"RE365 {resource}: device reported timeout"
            )

        if result.get("success") is not True:
            errorcode = result.get("errorcode", "unknown")

            if resource == "login.json":
                raise AuthorizeError(
                    f"RE365: login rejected (code={errorcode})"
                )

            raise ClientException(
                f"RE365 {resource}: API error (code={errorcode})"
            )
        return result

    def _read_data(self, resource: str) -> dict:
        """Read an endpoint and return its validated 'data' object."""
        result = self._post(
            resource,
            {"operation": "read"}
        )

        data = result.get("data")

        if not isinstance(data, dict):
            raise ClientException(
                f"RE365 {resource}: missing or invalid data"
            )

        return data

    def authorize(self) -> None:
        """Authenticate using the nonce stored in the RE365's COOKIE cookie."""
        if self._authorized:
            return

        # Never reuse a nonce from a previous or failed authentication attempt.
        self._session.cookies.clear()

        try:
            response = self._session.get(
                f"{self.host}/webpages/",
                timeout=self.timeout,
            )
            response.raise_for_status()

            nonce = self._session.cookies.get("COOKIE")

            if not nonce:
                raise ClientException(
                    "RE365: COOKIE missing from initial response"
                )

            self._post("login.json", {
                "operation": "login",
                "encoded": _login_hash(self.password, nonce),
                "nonce": nonce,
            })

            self._authorized = True

        except Exception:
            # Preserve the original exception while discarding local session state.
            self._authorized = False
            self._session.cookies.clear()
            raise

    def supports(self) -> bool:
        """Identify the model without claiming other TP-Link devices."""
        supported = False
        try:
            self.authorize()
            firmware = self.get_firmware()
            supported = firmware.model.strip().upper() == "RE365"
            return supported

        except Exception as exc:
            if self._logger:
                self._logger.debug("RE365 detection failed: %s", exc)
            return False

        finally:
            # Keep the session for the selected client; release it otherwise.
            if not supported:
                try:
                    self.logout()
                except Exception as exc:
                    if self._logger:
                        self._logger.debug(
                            "RE365 logout after detection failed: %s", exc
                        )

    def get_status(self) -> Status:
        """Return active Wi-Fi associations and the RE365's LAN identity."""
        self.authorize()
        data = self._read_data("status.json")
        grid = data.get("wirelessGrid")
        if not isinstance(grid, list):
            raise ClientException("RE365: wirelessGrid missing from status response")
        count = data.get("wirelessCount")
        if isinstance(count, int) and count > 0 and not grid:
            raise ClientException(
                "RE365: wirelessCount indicates connected clients "
                "but wirelessGrid is empty"
            )
        # Malformed client data must fail the poll instead of reporting departures.
        devices = devices_from_wireless_grid(grid)
        status = Status()
        status.devices = devices
        status.wifi_clients_total = len(devices)
        status.clients_total = len(devices)
        status.wifi_2g_enable = data.get("wireless_2g_enable") == "on"
        status.wifi_5g_enable = data.get("wireless_5g_enable") == "on"
        # LAN MAC is retrieved separately; the status endpoint does not include it.
        lan_data = self._read_data("status_lan_ipv4.json")

        status._lan_macaddr = get_mac(lan_data["lan_macaddr"])

        return status

    def get_firmware(self) -> Firmware:
        """Read model, hardware version, and firmware version from the RE365."""
        self.authorize()

        data = self._read_data("firmware.set.json")

        return Firmware(
            hardware_version=data["hardware_version"],
            model=data["model"],
            firmware_version=data["firmware_version"]
        )

    def logout(self) -> None:
        """Request logout and discard local session state even on HTTP failure."""
        if not self._authorized:
            return

        try:
            response = self._session.post(
                f"{self.host}/webpages/data/logout.json",
                data={"operation": "write"},
                timeout=self.timeout,
            )
            response.raise_for_status()
        finally:
            # Server-side logout may have failed; never reuse this local session.
            self._authorized = False
            self._session.cookies.clear()

    def get_ipv4_status(self):
        raise NotImplementedError("RE365 IP status not implemented")

    def reboot(self) -> None:
        raise NotImplementedError("RE365 reboot not implemented")

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        raise NotImplementedError("RE365 Wi-Fi control not implemented")
