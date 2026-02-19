# Tested on firmware 2.2.3 Build 20201110 Rel. 66916 (5553)

from hashlib import md5
from logging import Logger
import re
from time import time
from urllib.parse import urlparse

from requests import Session

from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.dataclass import Device, Firmware, IPv4Status, Status
from tplinkrouterc6u.common.exception import AuthorizeError, ClientError, ClientException
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


_PATH_VERSION = "/data/version.json"
_PATH_DEV_INFO = "/data/info.json"
_PATH_STATION = "/data/station.json"
_PATH_INTERFACES = "/data/interfaces.json"
_PATH_REBOOT = "/data/configReboot.json"
_PATH_WIRELESS_AP = "/data/wirelessAp.json"


class TPLinkCPE210Client(AbstractRouter):
    ROUTER_NAME = "TP-Link CPE210"

    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        logger: Logger = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        parsed = urlparse(self.host)
        netloc = parsed.netloc or parsed.path
        if netloc.endswith(":443"):
            netloc = netloc[: -len(":443")]
        self.host = f"http://{netloc}".rstrip("/")
        self._session = Session()
        self._logged = False
        self._headers = {
            "Referer": f"{self.host}/",
            "X-Requested-With": "XMLHttpRequest",
        }

    def supports(self) -> bool:
        try:
            self.authorize()
            self._get_data(_PATH_DEV_INFO, operation="load", id="info")
            return True
        except Exception:
            return False
        finally:
            try:
                self.logout()
            except Exception:
                pass

    def authorize(self) -> None:
        try:
            seed = self._session.get(
                f"{self.host}{_PATH_VERSION}",
                headers=self._headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self._verify_ssl,
            )

            if seed.status_code != 200:
                raise AuthorizeError("Cannot seed nonce")

            cookie = seed.cookies.get("COOKIE")
            if not cookie:
                raise AuthorizeError("Missing nonce cookie")

            # UI code uses the raw value of the COOKIE cookie as the submitStr/nonce.
            nonce = str(cookie)

            password_md5 = md5(self.password.encode("utf-8")).hexdigest()
            prehash = f"{password_md5.upper()}:{nonce}"
            encoded = f"{self.username}:{md5(prehash.encode('utf-8')).hexdigest().upper()}"

            response = self._session.post(
                f"{self.host}{_PATH_VERSION}",
                headers=self._headers,
                data={"encoded": encoded, "nonce": nonce},
                timeout=self.timeout,
                allow_redirects=False,
                verify=self._verify_ssl,
            )
            if response.status_code != 200:
                raise AuthorizeError("Login failed")

            try:
                payload = response.json()
            except Exception as e:
                raise AuthorizeError("Login returned invalid JSON") from e

            if not isinstance(payload, dict) or not payload.get("success"):
                raise AuthorizeError("Login failed")

            if payload.get("timeout") is True:
                raise AuthorizeError("Login timed out")

            # 0 indicates success in the UI.
            status = payload.get("status")
            if status is not None and status != 0:
                raise AuthorizeError(f"Login failed (status={status})")
        except ClientException:
            raise
        except Exception as e:
            raise AuthorizeError(str(e)) from e

        self._logged = True

    def logout(self) -> None:
        self._logged = False
        try:
            self._session.cookies.clear()
        except Exception:
            pass

    def get_firmware(self) -> Firmware:
        # Observed payloads:
        # - /data/info.json contains hardVersion/firmVersion
        # - /data/version.json contains devInfo/devVer/version (UI/build identifier)
        info = self._device_info()
        try:
            ver = self._get_data(_PATH_VERSION)
        except Exception:
            ver = {}

        hardware = (
            _first_text(info, ["hardVersion", "hardVer", "hardware", "hardwareVersion", "hw_ver"])
            or _first_text(ver, ["hardVersion", "hardVer", "hardware", "hardwareVersion", "hw_ver"])
            or (
                f"{_first_text(ver, ['devInfo'])} v{_first_text(ver, ['devVer'])}".strip(" v")
                if isinstance(ver, dict)
                else ""
            )
            or _first_text(ver, ["devVer"])
            or ""
        )

        model = self.ROUTER_NAME

        firmware = (
            _first_text(info, ["firmVersion", "firmware", "firmwareVersion", "softVer", "softVersion"])
            or _first_text(ver, ["firmVersion", "firmware", "firmwareVersion", "softVer", "softVersion"])
            or _first_text(ver, ["version"])
            or ""
        )

        return Firmware(str(hardware), str(model), str(firmware))

    def get_status(self) -> Status:
        stations = self._get_data(_PATH_STATION, operation="load")
        station_devices: list[Device] = []
        if isinstance(stations, list):
            for item in stations:
                if not isinstance(item, dict):
                    continue
                mac = (item.get("mac") or item.get("MAC") or "").replace("-", ":")
                ip = item.get("ip") or item.get("IP") or "0.0.0.0"
                hostname = (
                    item.get("hostname")
                    or item.get("hostName")
                    or item.get("deviceName")
                    or item.get("name")
                    or ""
                )
                if not mac:
                    continue

                dev = Device(Connection.UNKNOWN, get_mac(mac), get_ip(ip), hostname)

                txrx = item.get("txrxRate")
                if isinstance(txrx, str) and "/" in txrx:
                    left, right = txrx.split("/", 1)
                    try:
                        dev.tx_rate = int(float(left.strip()))
                    except Exception:
                        pass
                    try:
                        dev.rx_rate = int(float(right.strip()))
                    except Exception:
                        pass

                sn = item.get("signalNoiseCombined")
                if isinstance(sn, str) and "," in sn:
                    sig, _noise = sn.split(",", 1)
                    try:
                        dev.signal = int(float(sig.strip()))
                    except Exception:
                        pass

                station_devices.append(dev)

        interfaces = self._get_data(_PATH_INTERFACES, operation="load")
        interface_devices: list[Device] = []
        if isinstance(interfaces, list):
            for iface in interfaces:
                if not isinstance(iface, dict):
                    continue
                name = str(iface.get("interface") or "").strip() or "IF"
                mac = str(iface.get("mac") or "00:00:00:00:00:00").strip()
                ip = str(iface.get("ip") or "0.0.0.0").strip()

                dev = Device(
                    Connection.UNKNOWN,
                    get_mac(mac),
                    get_ip(ip),
                    f"IF:{name}",
                )
                dev.active = False

                dev.packets_received = _safe_int(iface.get("rxPacket"))
                dev.packets_sent = _safe_int(iface.get("txPacket"))

                rx_bytes = _parse_cpe_size_to_bytes(iface.get("rxBytes"))
                tx_bytes = _parse_cpe_size_to_bytes(iface.get("txBytes"))
                if rx_bytes is not None or tx_bytes is not None:
                    dev.traffic_usage = int((rx_bytes or 0) + (tx_bytes or 0))

                interface_devices.append(dev)

        status = Status()
        status.devices = [*station_devices, *interface_devices]
        status.clients_total = len(station_devices)
        status.wifi_clients_total = len(station_devices)
        status.wired_total = 0
        status.guest_clients_total = 0
        return status

    def get_ipv4_status(self) -> IPv4Status:
        info = self._device_info()
        ipv4 = IPv4Status()
        ipv4._lan_ipv4_ipaddr = get_ip(info.get("lanIpAddress") or info.get("lan_ip") or "0.0.0.0")
        ipv4._lan_ipv4_netmask = get_ip(info.get("lanSubnetMask") or info.get("lan_mask") or "0.0.0.0")
        ipv4._lan_macaddr = get_mac(info.get("lanMacAddr") or info.get("lan_mac") or "00:00:00:00:00:00")
        return ipv4

    def reboot(self) -> None:
        self._get_data(_PATH_REBOOT)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        if wifi != Connection.HOST_2G:
            raise ClientError("Only HOST_2G is supported for CPE210")

        current = self._get_data(_PATH_WIRELESS_AP)
        data: dict
        if isinstance(current, dict):
            data = dict(current)
        else:
            data = {}

        data["wirelessEnable"] = int(bool(enable))
        self._post_data(_PATH_WIRELESS_AP, data=data)

    def _post_data(self, path: str, data: dict, **params):
        params = {**params, "_": int(time() * 1000)}
        response = self._session.post(
            f"{self.host}{path}",
            headers=self._headers,
            params=params,
            data=data,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        if response.status_code != 200:
            raise ClientException(f"Unexpected response: {response.status_code}")

        try:
            payload = response.json()
        except Exception as e:
            raise ClientException("Invalid JSON response") from e

        if not isinstance(payload, dict) or not payload.get("success"):
            raise ClientException("Request failed")

        if payload.get("timeout") is True:
            raise AuthorizeError("Session timed out")
        return payload.get("data", payload)

    def _get_data(self, path: str, **params):
        params = {**params, "_": int(time() * 1000)}
        response = self._session.get(
            f"{self.host}{path}",
            headers=self._headers,
            params=params,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        if response.status_code != 200:
            raise ClientException(f"Unexpected response: {response.status_code}")

        try:
            payload = response.json()
        except Exception as e:
            raise ClientException("Invalid JSON response") from e

        if not isinstance(payload, dict) or not payload.get("success"):
            raise ClientException("Request failed")

        if payload.get("timeout") is True:
            raise AuthorizeError("Session timed out")
        return payload.get("data", payload)

    def _device_info(self) -> dict:
        data = self._get_data(_PATH_DEV_INFO, operation="load", id="info")
        return data if isinstance(data, dict) else {}


def _first_str(data: dict, keys: list[str]) -> str | None:
    for key in keys:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _first_text(data: dict, keys: list[str]) -> str | None:
    for key in keys:
        val = data.get(key)
        if val is None:
            continue
        if isinstance(val, str):
            if val.strip():
                return val.strip()
            continue
        # Numbers/bools sometimes appear in version payloads.
        return str(val)
    return None


_REGEX_SIZE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?)\s*$", re.IGNORECASE)


def _parse_cpe_size_to_bytes(value) -> int | None:
    """Parse CPE210 size strings like '36G', '11M' into bytes.

    Observed fields: rxBytes/txBytes return a number + unit suffix.
    We interpret K/M/G/T/P using 1024-based units.
    """

    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s or s.lower() in {"n/a", "na"}:
        return None

    m = _REGEX_SIZE.match(s)
    if not m:
        return None

    number = float(m.group(1))
    unit = (m.group(2) or "").upper()

    scale = {
        "": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "P": 1024**5,
    }.get(unit)
    if scale is None:
        return None
    return int(number * scale)


def _safe_int(value) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None
