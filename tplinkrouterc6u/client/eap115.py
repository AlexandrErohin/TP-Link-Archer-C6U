from hashlib import md5
from logging import Logger
from time import time

from requests import Session

from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.dataclass import Device, Firmware, IPv4Status, Status
from tplinkrouterc6u.common.exception import AuthorizeError, ClientError, ClientException
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


_PATH_CLIENT_LIST = "/data/monitor.client.client.json"
_PATH_AP_LIST = "/data/monitor.ap.aplist.json"
_PATH_DEV_INFO = "/data/monitor.ap.devinfo.json"
_PATH_AP_LAN_INFO = "/data/monitor.ap.laninfo.json"


class TPLinkEAP115Client(AbstractRouter):
    ROUTER_NAME = "TP-Link EAP115"

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
        self.host = self.host.rstrip("/")
        self._session = Session()
        self._logged = False
        self._headers = {"Referer": f"{self.host}/"}

    def supports(self) -> bool:
        try:
            self.authorize()
            self._get_data(_PATH_AP_LIST, operation="load")
            return True
        except Exception:
            return False
        finally:
            try:
                self.logout()
            except Exception:
                pass

    def authorize(self) -> None:
        password_md5 = md5(self.password.encode("utf-8")).hexdigest().upper()
        try:
            response = self._session.get(
                f"{self.host}/",
                headers=self._headers,
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if response.status_code != 200:
                raise AuthorizeError(f"Cannot connect to {self.host}")

            response = self._session.post(
                f"{self.host}/",
                headers=self._headers,
                data={"username": self.username, "password": password_md5},
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if response.status_code != 200:
                raise AuthorizeError("Login failed")
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
        ap = self._first_access_point()
        ap_mac = ap.get("MAC") if isinstance(ap, dict) else ""

        try:
            info = self._device_info(ap_mac)
        except Exception:
            info = {}

        hardware = (
            _first_str(info, ["hardware", "hardwareVersion", "HardVer", "hardVer", "hardVersion", "hw_ver"])
            or _first_str(ap, ["hardware", "hardwareVersion", "HardVer", "hardVer", "hardVersion", "hw_ver"])
            or ""
        )
        model = _first_str(info, ["model", "modelName", "product", "name"]) or self.ROUTER_NAME
        firmware = _first_str(info, ["firmware", "firmwareVersion", "softVer", "softVersion", "version"]) or ""
        return Firmware(hardware, model, firmware)

    def get_status(self) -> Status:
        ap = self._first_access_point()
        ap_mac = ap.get("MAC") if isinstance(ap, dict) else ""
        try:
            clients = (
                self._get_data(_PATH_CLIENT_LIST, operation="load", apMac=ap_mac)
                if ap_mac
                else self._get_data(_PATH_CLIENT_LIST, operation="load")
            )
        except Exception:
            clients = []

        devices: list[Device] = []
        if isinstance(clients, list):
            for item in clients:
                if not isinstance(item, dict):
                    continue
                mac = (item.get("MAC") or item.get("mac") or "").replace("-", ":")
                ip = item.get("IP") or item.get("ip") or "0.0.0.0"
                hostname = item.get("name") or item.get("NAME") or item.get("hostName") or ""
                if mac:
                    devices.append(Device(Connection.UNKNOWN, get_mac(mac), get_ip(ip), hostname))

        status = Status()
        status.devices = devices
        status.clients_total = len(devices)
        status.wifi_clients_total = len(devices)
        return status

    def get_ipv4_status(self) -> IPv4Status:
        ap = self._first_access_point()
        ap_mac = ap.get("MAC") if isinstance(ap, dict) else ""
        try:
            info = self._ap_lan_info(ap_mac)
        except Exception:
            info = {}
        ipv4 = IPv4Status()

        if isinstance(info, dict):
            ipv4._lan_ipv4_ipaddr = get_ip(info.get("ip") or info.get("IP") or "0.0.0.0")
            ipv4._lan_ipv4_netmask = get_ip(info.get("mask") or info.get("netmask") or "0.0.0.0")
            ipv4._wan_ipv4_gateway = get_ip(info.get("gateway") or "0.0.0.0")
            ipv4._lan_macaddr = get_mac(info.get("mac") or info.get("MAC") or "00:00:00:00:00:00")

        return ipv4

    def reboot(self) -> None:
        raise ClientError("Reboot is not supported for EAP115")

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        raise ClientError("WiFi configuration is not supported for EAP115")

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
        return payload.get("data")

    def _access_points(self) -> list[dict]:
        aps = self._get_data(_PATH_AP_LIST, operation="load")
        return aps if isinstance(aps, list) else []

    def _first_access_point(self) -> dict:
        try:
            aps = self._access_points()
        except Exception:
            return {}
        if not aps:
            return {}
        return aps[0] if isinstance(aps[0], dict) else {}

    def _device_info(self, ap_mac: str = "") -> dict:
        if not ap_mac:
            return {}

        data = self._get_data(_PATH_DEV_INFO, operation="read", apMac=ap_mac)
        if isinstance(data, list) and data:
            return data[0] if isinstance(data[0], dict) else {}
        return data if isinstance(data, dict) else {}

    def _ap_lan_info(self, ap_mac: str = "") -> dict:
        if not ap_mac:
            return {}
        data = self._get_data(_PATH_AP_LAN_INFO, operation="read", apMac=ap_mac)
        return data if isinstance(data, dict) else {}


def _first_str(data: dict, keys: list[str]) -> str | None:
    for key in keys:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None
