# Note: tested on firmware 1.0.0 Build 20230218 Rel.50633

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from logging import Logger

from requests import Session
from macaddress import EUI48

from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.dataclass import Firmware, IPv4Status, PortStatus, Status
from tplinkrouterc6u.common.exception import AuthorizeError, ClientError
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


_PATH_LOGIN = "/logon.cgi"
_PATH_SYS_INFO = "/SystemInfoRpm.htm"
_PATH_PORT_STATS = "/PortStatisticsRpm.htm"
_PATH_PORT_SETTINGS = "/PortSettingRpm.htm"
_PATH_IP_SETTINGS = "/IpSettingRpm.htm"
_PATH_LED_STATUS = "/TurnOnLEDRpm.htm"
_PATH_LED_SET = "/led_on_set.cgi"
_PATH_REBOOT = "/reboot.cgi"


class TPLinkSG108EClient(AbstractRouter):
    ROUTER_NAME = "TP-Link TL-SG108E"

    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        logger: Logger | None = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self.host = self.host.rstrip("/")
        self._session = Session()
        self._logged = False
        self._headers = {"Referer": f"{self.host}/"}
        self._lan_mac: EUI48 | None = None
        self._lan_mac_resolved = False

    def supports(self) -> bool:
        try:
            self.authorize()
            vars = self._get_vars(_PATH_SYS_INFO)
            title = str(vars.get("g_title") or "")
            if "TL-SG" in title:
                return True
            info = vars.get("info_ds")
            if isinstance(info, dict):
                flat = _flatten_dict(info)
                hardware = flat.get("hardwareStr")
                if isinstance(hardware, str) and "TL-SG" in hardware:
                    return True
                descr = flat.get("descriStr")
                return isinstance(descr, str) and "TL-SG" in descr
            return False
        except Exception:
            return False
        finally:
            try:
                self.logout()
            except Exception:
                pass

    def authorize(self) -> None:
        try:
            r = self._session.get(
                f"{self.host}/",
                headers=self._headers,
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if r.status_code != 200:
                raise AuthorizeError("Cannot connect")

            r = self._session.post(
                f"{self.host}{_PATH_LOGIN}",
                headers=self._headers,
                data={
                    "username": self.username,
                    "password": self.password,
                    "cpassword": "",
                    "logon": "Login",
                },
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if r.status_code != 200:
                raise AuthorizeError("Login failed")
        except AuthorizeError:
            raise
        except Exception as e:
            raise AuthorizeError(str(e))

        self._logged = True

    def logout(self) -> None:
        self._logged = False
        try:
            self._session.cookies.clear()
        except Exception:
            pass

    def get_firmware(self) -> Firmware:
        info = self.device_info()
        model = info.get("descriStr") or self.ROUTER_NAME
        hardware = info.get("hardwareStr") or ""
        firmware = info.get("firmwareStr") or ""
        return Firmware(str(hardware), str(model), str(firmware))

    def get_status(self) -> Status:
        stats = self.port_stats()
        ports_total = _safe_int(stats.get("max_port_num"), default=0)

        all_info = stats.get("all_info") if isinstance(stats, dict) else None
        state = all_info.get("state") if isinstance(all_info, dict) else None
        link_status = all_info.get("link_status") if isinstance(all_info, dict) else None

        ports_link_up = _count_ports_link_up(link_status, state, ports_total)

        status = Status()
        # For switches, treat port counts as the closest equivalent to “wired clients”.
        status.wired_total = ports_total
        status.clients_total = ports_link_up
        status.wifi_clients_total = 0
        status.guest_clients_total = 0
        status.devices = []
        status._lan_macaddr = self._resolve_lan_mac()

        return status

    def _resolve_lan_mac(self) -> EUI48 | None:
        if not self._lan_mac_resolved:
            try:
                mac = self.device_info().get("macStr")
                if mac:
                    self._lan_mac = get_mac(mac)
            except Exception:
                pass
        self._lan_mac_resolved = True
        return self._lan_mac

    def get_ipv4_status(self) -> IPv4Status:
        settings = self.ip_settings()
        ipv4 = IPv4Status()
        ipv4._lan_ipv4_ipaddr = get_ip(settings.get("ipStr") or settings.get("ip") or "0.0.0.0")
        ipv4._lan_ipv4_netmask = get_ip(settings.get("netmaskStr") or settings.get("netmask") or "0.0.0.0")
        ipv4._wan_ipv4_gateway = get_ip(settings.get("gatewayStr") or settings.get("gateway") or "0.0.0.0")
        mac = settings.get("macStr") or settings.get("mac")
        if not mac:
            mac = self.device_info().get("macStr")
        ipv4._lan_macaddr = get_mac(mac or "00:00:00:00:00:00")
        return ipv4

    def get_port_status(self) -> list[PortStatus]:
        """Return per-port status for TL-SG108E (tested on v6.0).

        Requires authorize(). Performs two HTTP requests (port_stats and port_settings).
        Packet counters are packet counts, not bytes, and may be reset by the switch.
        """
        stats = self.port_stats()
        settings = self.port_settings()
        count = _physical_port_count(stats, settings)
        if count <= 0:
            return []

        stats_info = _as_dict(stats.get("all_info") if isinstance(stats, dict) else None)
        settings_info = _as_dict(settings.get("all_info") if isinstance(settings, dict) else None)
        stats_state = stats_info.get("state")
        settings_state = settings_info.get("state")
        link_status = stats_info.get("link_status")
        spd_cfg = settings_info.get("spd_cfg")
        spd_act = settings_info.get("spd_act")
        fc_cfg = settings_info.get("fc_cfg")
        fc_act = settings_info.get("fc_act")
        trunk = settings_info.get("trunk_info")
        pkts = stats_info.get("pkts")

        ports: list[PortStatus] = []
        for i in range(count):
            enabled = _enabled_at(stats_state, settings_state, i)
            auto_neg, cfg_speed, cfg_duplex = _configured_mode(_at(spd_cfg, i))
            neg_speed, neg_duplex = _negotiated_mode(_at(spd_act, i))
            base = i * 4
            ports.append(
                PortStatus(
                    port=i + 1,
                    enabled=enabled,
                    link_up=_link_up(enabled, _at(link_status, i)),
                    auto_negotiation=auto_neg,
                    configured_speed=cfg_speed,
                    configured_duplex=cfg_duplex,
                    negotiated_speed=neg_speed,
                    negotiated_duplex=neg_duplex,
                    flow_control_enabled=_bool01(_at(fc_cfg, i)),
                    flow_control_active=_bool01(_at(fc_act, i)),
                    lag=_lag(_at(trunk, i)),
                    tx_good_packets=_parse_int(_at(pkts, base)),
                    tx_bad_packets=_parse_int(_at(pkts, base + 1)),
                    rx_good_packets=_parse_int(_at(pkts, base + 2)),
                    rx_bad_packets=_parse_int(_at(pkts, base + 3)),
                )
            )
        return ports

    def reboot(self) -> None:
        r = self._session.post(
            f"{self.host}{_PATH_REBOOT}",
            headers=self._headers,
            data={"reboot_op": "reboot", "save_op": 1, "apply": "Reboot"},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        if r.status_code != 200:
            raise ClientError("Reboot failed")

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        raise ClientError("WiFi configuration is not supported for TL-SG108E")

    def port_stats(self) -> dict:
        return self._get_vars(_PATH_PORT_STATS)

    def port_settings(self) -> dict:
        return self._get_vars(_PATH_PORT_SETTINGS)

    def ip_settings(self) -> dict:
        data = self._get_vars(_PATH_IP_SETTINGS)
        ip_ds = data.get("ip_ds")
        return _flatten_dict(ip_ds) if isinstance(ip_ds, dict) else {}

    def device_info(self) -> dict:
        data = self._get_vars(_PATH_SYS_INFO)
        info_ds = data.get("info_ds")
        return _flatten_dict(info_ds) if isinstance(info_ds, dict) else {}

    def led_status(self) -> bool:
        data = self._get_vars(_PATH_LED_STATUS)
        return bool(data.get("led"))

    def set_led(self, enable: bool) -> bool:
        data = self._get_vars(_PATH_LED_SET, params={"rd_led": int(enable), "led_cfg": "Apply"})
        return bool(data.get("led"))

    def _get_vars(self, path: str, params: dict | None = None) -> dict:
        r = self._session.get(
            f"{self.host}{path}",
            headers=self._headers,
            params=params,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        if r.status_code != 200:
            raise ClientError(f"Unexpected response: {r.status_code}")

        vars = parse_script_variables(r.text)
        vars.pop("tip", None)
        return vars


def _flatten_dict(data: dict) -> dict:
    out: dict = {}
    for k, v in data.items():
        out[k] = v[0] if isinstance(v, (list, tuple)) and len(v) == 1 else v
    return out


class _ScriptExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_script = False
        self.scripts: list[str] = []
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "script":
            self._in_script = True
            self._buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            body = "".join(self._buf)
            if body.strip():
                self.scripts.append(body)
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buf.append(data)


_REGEX_JS_VARS = re.compile(r"\bvar\s+(\w+)\s*=\s*([\s\S]+?)(?:;|$)")
_REGEX_JS_DICT_KEY = re.compile(r"(^|,)\s*([A-Za-z_]\w*)\s*:")
_REGEX_MULTI_VAR_REST = re.compile(r",\s*\w+\s*=")


def parse_script_variables(html: str) -> dict:
    """Parse JavaScript variable declarations from HTML.

    TL-SG108E (and related Easy Smart Switches) embed data in HTML pages as JavaScript `var` assignments.
    This is a pragmatic parser intended for those pages; it is not a full JavaScript parser.
    """

    output: dict = {}
    if not html:
        return output

    extractor = _ScriptExtractor()
    extractor.feed(html)

    for script_body in extractor.scripts:
        js = _fix_semicolons(script_body)
        for js_name, js_val in _REGEX_JS_VARS.findall(js):
            output.update(_parse_single_assignment(js_name, js_val))

    return output


def _fix_semicolons(js: str) -> str:
    lines = [line.strip() for line in js.splitlines() if line.strip()]

    for i in range(1, len(lines)):
        if lines[i].startswith("var") and not lines[i - 1].endswith(";"):
            lines[i - 1] = f"{lines[i - 1]};"

    return "\n".join(lines)


def _parse_single_assignment(name: str, raw_value: str) -> dict:
    raw = raw_value.strip().replace("'", '"')

    # Support JS multi-var declaration like: var a=1,b=2;
    # Only trigger this path when we see additional named assignments after commas.
    if _REGEX_MULTI_VAR_REST.search(raw):
        try:
            return _handle_multiple_vars(name, raw)
        except Exception:
            pass

    if raw.startswith("{"):
        try:
            return {name: _handle_dict(raw)}
        except Exception:
            return {}

    if raw.startswith("new Array"):
        try:
            return {name: _handle_array(raw)}
        except Exception:
            return {}

    try:
        return {name: json.loads(raw)}
    except Exception:
        return {}


def _handle_dict(val: str):
    body = val[1:-1].strip()
    body = body.replace("'", '"')
    body = _REGEX_JS_DICT_KEY.sub(r'\1"\2":', body)
    body = body.rstrip().rstrip(",")
    return json.loads("{" + body + "}")


def _handle_array(val: str):
    inner = val.strip()
    if not inner.startswith("new Array("):
        raise ValueError("Not an array")

    inner = inner[len("new Array("):]
    if inner.endswith(")"):
        inner = inner[:-1]

    if not inner.strip():
        return []

    parts = _split_top_level(inner)
    out: list = []
    for part in parts:
        item = part.strip()
        if not item:
            continue
        try:
            out.append(json.loads(item))
        except Exception:
            out.append(item.strip('"'))
    return out


def _handle_multiple_vars(name: str, val: str) -> dict:
    vars_all = f"{name}={val}"
    out: dict = {}
    for var_def in _split_top_level(vars_all):
        if "=" not in var_def:
            continue
        k, v = var_def.split("=", 1)
        key = k.strip()
        raw_value = v.strip().replace("'", '"')
        out[key] = _parse_js_value(raw_value)
    return out


def _parse_js_value(raw: str):
    raw = raw.strip()
    if not raw:
        return None

    if raw.startswith("new Array"):
        return _handle_array(raw)

    if raw.startswith("{"):
        return _handle_dict(raw)

    try:
        return json.loads(raw)
    except Exception:
        return raw.strip('"')


def _split_top_level(s: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []

    paren = 0
    brace = 0
    bracket = 0
    in_str = False
    escape = False

    for ch in s:
        if in_str:
            buf.append(ch)
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_str = False
            continue

        if ch == '"':
            in_str = True
            buf.append(ch)
            continue

        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)

        if ch == "," and paren == 0 and brace == 0 and bracket == 0:
            parts.append("".join(buf))
            buf = []
            continue

        buf.append(ch)

    if buf:
        parts.append("".join(buf))
    return parts


_SPEED_DUPLEX = {
    2: (10, "half"),
    3: (10, "full"),
    4: (100, "half"),
    5: (100, "full"),
    6: (1000, "full"),
}
_LINK_UP_CODES = {1, 2, 3, 4, 5, 6}


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _parse_int(value) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _at(seq, index: int):
    if not isinstance(seq, list) or index < 0 or index >= len(seq):
        return None
    return seq[index]


def _bool01(value) -> bool | None:
    parsed = _parse_int(value)
    if parsed == 0:
        return False
    if parsed == 1:
        return True
    return None


def _physical_port_count(stats, settings) -> int:
    for data in (stats, settings):
        if not isinstance(data, dict):
            continue
        n = _parse_int(data.get("max_port_num"))
        if n is not None and n > 0:
            return n
    return 0


def _enabled_at(stats_state, settings_state, index: int) -> bool | None:
    enabled = _bool01(_at(stats_state, index))
    if enabled is not None:
        return enabled
    return _bool01(_at(settings_state, index))


def _link_up(enabled: bool | None, code) -> bool | None:
    if enabled is False:
        return False
    parsed = _parse_int(code)
    if parsed is None:
        return None
    if parsed == 0:
        return False
    if parsed in _LINK_UP_CODES:
        return True
    return None


def _configured_mode(code) -> tuple[bool | None, int | None, str | None]:
    parsed = _parse_int(code)
    if parsed == 1:
        return True, None, None
    decoded = _SPEED_DUPLEX.get(parsed) if parsed is not None else None
    if decoded is None:
        return None, None, None
    return False, decoded[0], decoded[1]


def _negotiated_mode(code) -> tuple[int | None, str | None]:
    parsed = _parse_int(code)
    decoded = _SPEED_DUPLEX.get(parsed) if parsed is not None else None
    if decoded is None:
        return None, None
    return decoded


def _lag(value) -> int | None:
    parsed = _parse_int(value)
    if parsed is None or parsed <= 0:
        return None
    return parsed


def _count_ports_enabled(state, ports_total: int) -> int:
    if not isinstance(state, list) or ports_total <= 0:
        return 0
    return sum(1 for x in state[:ports_total] if _safe_int(x, default=0) == 1)


def _count_ports_link_up(link_status, state, ports_total: int) -> int:
    if not isinstance(link_status, list) or ports_total <= 0:
        return 0
    enabled = state if isinstance(state, list) else None
    total = 0
    for i, v in enumerate(link_status[:ports_total]):
        if enabled is not None and i < len(enabled) and _safe_int(enabled[i], default=0) != 1:
            continue
        if _safe_int(v, default=0) != 0:
            total += 1
    return total
