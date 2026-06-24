import re
from logging import Logger
from urllib import parse
from urllib.parse import urlparse

from tplinkrouterc6u.client.c80 import TplinkC80Router
from tplinkrouterc6u.common.dataclass import Device, Status
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


class TplinkWR844NRouter(TplinkC80Router):
    """Client for TL-WR844N firmware that returns plaintext C80-style data."""

    BLOCK_REGEX = re.compile(r'id (\d+\|\d,\d,\d)\r\n(.*?)(?=\r\nid \d+\||$)', re.DOTALL)

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

    def supports(self) -> bool:
        try:
            response = self.request(2, 1, data='0|1,0,0')
            return response.status_code == 200 and self._is_wr844n_response(response.text)
        except Exception:
            return False

    def get_status(self) -> Status:
        request_text = '#'.join([
            '1|1,0,0',
            '4|1,0,0',
            '9|1,0,0',
            '23|1,0,0',
            '0|1,0,0',
        ])
        response_text = self._request_plaintext(request_text)
        data_blocks = self._parse_data_blocks(response_text)

        mac_info = self._parse_last_values_from_block(data_blocks.get('1|1,0,0', []))
        lan_info = self._parse_last_values_from_block(data_blocks.get('4|1,0,0', []))
        wan_info = self._parse_last_values_from_block(data_blocks.get('23|1,0,0', []))

        devices = self._parse_dhcp_devices(data_blocks.get('9|1,0,0', []))

        status = Status()
        status._lan_macaddr = get_mac(mac_info.get('mac 0', '00-00-00-00-00-00'))
        status._wan_macaddr = get_mac(mac_info.get('mac 1', '00-00-00-00-00-00'))
        status._lan_ipv4_addr = get_ip(lan_info.get('ip') or self._host_ip())
        status._wan_ipv4_addr = get_ip(wan_info.get('ip') or self._host_ip())

        gateway = wan_info.get('gateway') or lan_info.get('gateway')
        if gateway and gateway != '0.0.0.0':
            status._wan_ipv4_gateway = get_ip(gateway)

        uptime = wan_info.get('upTime')
        status.wan_ipv4_uptime = int(uptime) // 100 if uptime and uptime.isdigit() else None
        status.devices = devices
        status.wired_total = 0
        status.wifi_clients_total = len(devices)
        status.clients_total = len(devices)
        status.wifi_2g_enable = True
        status.conn_type = 'Router/AP'
        return status

    def _request_plaintext(self, text: str) -> str:
        body = self._encrypt_body(text)
        response = self.request(2, 1, True, data=body)
        return self._decrypt_data(response.text)

    def _decrypt_data(self, encrypted_text: str) -> str:
        if self._is_plain_response(encrypted_text):
            return encrypted_text
        return super()._decrypt_data(encrypted_text)

    def _parse_data_blocks(self, response_text: str) -> dict[str, list[str]]:
        matches = TplinkWR844NRouter.BLOCK_REGEX.findall(response_text)
        return {match[0]: [line for line in match[1].strip().split('\r\n') if line] for match in matches}

    def _parse_dhcp_devices(self, response_data: list[str]) -> list[Device]:
        devices: list[Device] = []
        for item in self._parse_response_to_dict(response_data):
            ip = item.get('ip')
            mac = item.get('mac')
            if not ip or not mac or mac == '00-00-00-00-00-00':
                continue
            devices.append(Device(Connection.HOST_2G, get_mac(mac), get_ip(ip),
                                  parse.unquote(item.get('hostName', ''))))
        return devices

    def _parse_last_values(self, text: str) -> dict[str, str]:
        return self._parse_last_values_from_block([line for line in text.splitlines() if line])

    def _parse_last_values_from_block(self, lines: list[str]) -> dict[str, str]:
        values: dict[str, str] = {}
        for line in lines:
            if line == '00000' or line.startswith('id '):
                continue
            key, _, value = line.rpartition(' ')
            if key:
                values[key] = value.strip()
        return values

    def _host_ip(self) -> str:
        return urlparse(self.host).hostname or '0.0.0.0'

    @staticmethod
    def _is_wr844n_response(text: str) -> bool:
        return TplinkWR844NRouter._is_plain_response(text) and 'modelName TL-WR844N' in text

    @staticmethod
    def _is_plain_response(text: str) -> bool:
        return isinstance(text, str) and text.startswith('00000\r\n')
