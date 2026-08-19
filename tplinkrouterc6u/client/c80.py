from logging import Logger
from urllib import parse
from collections import defaultdict
import re
import requests
from urllib.parse import urlparse
from requests import Session
from tplinkrouterc6u.common.helper import get_ip, get_ipv6, get_mac
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.dataclass import Firmware, Status, IPv4Status, IPv6Status, IPv4Reservation
from tplinkrouterc6u.common.dataclass import IPv4DHCPLease, Device, VPNStatus
from tplinkrouterc6u.client_abstract import AbstractRouter


class RouterConstants:
    AUTH_TOKEN_INDEX1 = 3
    AUTH_TOKEN_INDEX2 = 4

    HOST_WIFI_2G_REQUEST = '33|1,1,0'
    HOST_WIFI_5G_REQUEST = '33|2,1,0'
    GUEST_WIFI_2G_REQUEST = '33|1,2,0'
    GUEST_WIFI_5G_REQUEST = '33|2,2,0'
    IOT_WIFI_2G_REQUEST = '33|1,9,0'
    IOT_WIFI_5G_REQUEST = '33|2,9,0'
    IPV6_WAN_REQUEST = '45|1,0,0'
    IPV6_SITE_REQUEST = '48|1,0,0'

    CONNECTION_REQUESTS_MAP = {
            Connection.HOST_2G: HOST_WIFI_2G_REQUEST,
            Connection.HOST_5G: HOST_WIFI_5G_REQUEST,
            Connection.GUEST_2G: GUEST_WIFI_2G_REQUEST,
            Connection.GUEST_5G: GUEST_WIFI_5G_REQUEST,
            Connection.IOT_2G: IOT_WIFI_2G_REQUEST,
            Connection.IOT_5G: IOT_WIFI_5G_REQUEST
        }

    CONNECTION_TYPE_MAP = {
        '0': "Dynamic IP",
        '1': 'Static IP',
        '2': 'PPPoE',
        '3': 'L2TP',
        '4': 'PPTP'
    }

    CONNECTION_STATUS_MAP_IPV6 = {
        '0': "Disabled",
        '7': 'Disconnected',
        '8': 'Connecting',
        '9': 'Connected'
    }

    ADDR_TYPE_MAP_IPV6 = {
        '0': "Unknown",
        '1': 'DHCPv6'
    }


class RouterConfig:
    """Configuration parameters for the router."""
    ENCODING: str = ("yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8"
                     "ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70T"
                     "OoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW")
    KEY: str = "RDpbLfCPsJZ7fiv"
    PAD_CHAR: str = chr(187)


class EncryptionState:
    """Holds encryption-related state."""

    def __init__(self):
        self.nn_rsa = ''
        self.ee_rsa = ''
        self.seq = ''
        self.aes = EncryptionWrapper()
        self.token = ''


class TplinkC80Router(AbstractRouter):
    DATA_REGEX = re.compile(r'id (\d+\|\d,\d,\d)\r\n(.*?)(?=\r\nid \d+\||$)', re.DOTALL)

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._session = Session()
        self._session.verify = TplinkC80Router._build_ssl_context(self._verify_ssl)
        self._encryption = EncryptionState()
        self._wifi_request = None
        self._ipv6_support = True

    @staticmethod
    def _build_ssl_context(verify_ssl: bool):
        import ssl

        ctx = ssl.create_default_context()
        # C80 routers use OpenSSL legacy renegotiation, disabled by default on
        # Python 3.14+ (UNSAFE_LEGACY_RENEGOTIATION_DISABLED).
        if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        if verify_ssl is False:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def supports(self) -> bool:
        try:
            response = self.request(2, 1, data='0|1,0,0')
            return response.status_code == 200 and response.text.startswith('00000')
        except Exception:
            return False

    def authorize(self) -> None:
        encoded_password = TplinkC80Router._encrypt_password(self.password)

        # Get token encryption strings and encrypt the password
        response = self.request(2, 1)
        self._encryption.token = TplinkC80Router._encode_token(encoded_password, response)

        # Get RSA exponent, modulus and sequence number
        response = self.request(16, 0, data='get')

        responseText = response.text.splitlines()
        if len(responseText) < 4:
            raise ClientException("Invalid response for RSA keys from router")
        self._encryption.ee_rsa = responseText[1]
        self._encryption.nn_rsa = responseText[2]
        self._encryption.seq = responseText[3]

        # Encrypt AES string
        aes_string_encrypted = EncryptionWrapper.rsa_encrypt(self._encryption.aes._get_aes_string(),
                                                             self._encryption.nn_rsa,
                                                             self._encryption.ee_rsa)

        # Register AES string for decryption on server side
        self.request(16, 0, True, data=f'set {aes_string_encrypted}')
        # Some auth request, might be redundant
        response = self.request(7, 0, True)

    def logout(self) -> None:
        self.request(11, 0, True)

    def get_firmware(self) -> Firmware:
        text = '0|1,0,0'

        body = self._encrypt_body(text)

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)
        device_datamap = dict(line.split(" ", 1) for line in response_text.split("\r\n")[1:-1])

        return Firmware(parse.unquote(device_datamap['hardVer']), parse.unquote(device_datamap['modelName']),
                        parse.unquote(device_datamap['softVer']))

    def get_status(self) -> Status:
        if self._wifi_request is None:
            request = '13|1,0,0'
            self._wifi_request = request in self._return_data_block(request)

        return self._get_status_with_wifi() if self._wifi_request else self._get_status_without_wifi()

    def _get_status_with_wifi(self) -> Status:
        mac_info_request = "1|1,0,0"
        lan_ip_request = "4|1,0,0"
        wan_ip_request = "23|1,0,0"
        device_data_request = '13|1,0,0'
        all_requests = [
            mac_info_request, lan_ip_request, wan_ip_request, device_data_request,
            RouterConstants.HOST_WIFI_2G_REQUEST, RouterConstants.HOST_WIFI_5G_REQUEST,
            RouterConstants.GUEST_WIFI_2G_REQUEST, RouterConstants.GUEST_WIFI_5G_REQUEST,
            RouterConstants.IOT_WIFI_2G_REQUEST, RouterConstants.IOT_WIFI_5G_REQUEST
        ]
        request_text = '#'.join(all_requests)
        data_blocks = self._return_data_block(request_text)

        def extract_value(response_list, prefix):
            return next((s.split(prefix, 1)[1] for s in response_list if s.startswith(prefix)), None)

        network_info = {
            'lan_mac': extract_value(data_blocks[mac_info_request], "mac 0 "),
            'wan_mac': extract_value(data_blocks[mac_info_request], "mac 1 "),
            'lan_ip': extract_value(data_blocks[lan_ip_request], "ip "),
            'wan_ip': extract_value(data_blocks[wan_ip_request], "ip "),
            'gateway_ip': extract_value(data_blocks[wan_ip_request], "gateway "),
            'uptime': extract_value(data_blocks[wan_ip_request], "upTime ")
        }

        wifi_status = {}
        for key, request in RouterConstants.CONNECTION_REQUESTS_MAP.items():
            value = data_blocks.get(request)
            wifi_status[key] = extract_value(data_blocks.get(request), "bEnable ") == '1' if value else None

        device_data_response = data_blocks[device_data_request]

        mapped_devices = self._parse_devices(device_data_response)

        status = Status()
        status._wan_macaddr = get_mac(network_info['wan_mac'])
        status._lan_macaddr = get_mac(network_info['lan_mac'])
        status._lan_ipv4_addr = get_ip(network_info['lan_ip'])
        status._wan_ipv4_addr = get_ip(network_info['wan_ip'])
        status._wan_ipv4_gateway = get_ip(network_info['gateway_ip'])
        status.wan_ipv4_uptime = int(network_info['uptime']) // 100

        status.wifi_2g_enable = wifi_status[Connection.HOST_2G]
        status.wifi_5g_enable = wifi_status[Connection.HOST_5G]
        status.guest_2g_enable = wifi_status[Connection.GUEST_2G]
        status.guest_5g_enable = wifi_status[Connection.GUEST_5G]
        status.iot_2g_enable = wifi_status[Connection.IOT_2G]
        status.iot_5g_enable = wifi_status[Connection.IOT_5G]

        status.wired_total = sum(1 for device in mapped_devices if device.type == Connection.WIRED)
        status.wifi_clients_total = sum(1 for device in mapped_devices
                                        if device.type in (Connection.HOST_2G, Connection.HOST_5G))
        status.guest_clients_total = sum(1 for device in mapped_devices
                                         if device.type in (Connection.GUEST_2G, Connection.GUEST_5G))
        status.iot_clients_total = sum(1 for device in mapped_devices
                                       if device.type in (Connection.IOT_2G, Connection.IOT_5G))
        status.clients_total = (status.wired_total + status.wifi_clients_total +
                                status.guest_clients_total + status.iot_clients_total)

        status.devices = mapped_devices
        self._enrich_status_ipv6(status)
        return status

    def _get_status_without_wifi(self) -> Status:
        request_text = '#'.join([
            '1|1,0,0',
            '4|1,0,0',
            '9|1,0,0',
            '23|1,0,0',
            '0|1,0,0',
        ])
        data_blocks = self._return_data_block(request_text)

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
        self._enrich_status_ipv6(status)
        return status

    def _enrich_status_ipv6(self, status: Status) -> None:
        """Fill Status IPv6 fields via a separate WAN probe.

        Kept out of the main status batch: some firmwares reject unknown ids.
        On failure or a response without the WAN IPv6 block, disable further
        probes for this client instance (same pattern as MR _ipv6_support).
        """
        if not self._ipv6_support:
            return
        try:
            data_blocks = self._return_data_block(RouterConstants.IPV6_WAN_REQUEST)
            wan_lines = data_blocks.get(RouterConstants.IPV6_WAN_REQUEST) if data_blocks else None
            if not wan_lines:
                self._ipv6_support = False
                return
            ipv6_wan_info = self._parse_last_values_from_block(wan_lines)
            # Match get_ipv6_status: any non-'0' status means IPv6 is enabled.
            status.wan_ipv6_enabled = ipv6_wan_info.get('status', '0') != '0'
            status._wan_ipv6_addr = get_ipv6(ipv6_wan_info.get('globalIp', '::'))
        except Exception:
            self._ipv6_support = False

    def reboot(self) -> None:
        self.request(6, 1, True)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        enable_string = f'bEnable {int(enable)}'
        text = f'id {RouterConstants.CONNECTION_REQUESTS_MAP[wifi]}\r\n{enable_string}'
        body = self._encrypt_body(text)
        self.request(1, 0, True, data=body)

    def get_ipv4_status(self) -> IPv4Status:
        mac_info_request = "1|1,0,0"
        lan_ip_request = "4|1,0,0"
        dhcp_request = "8|1,0,0"
        link_type_request = "22|1,0,0"
        wan_ip_request = "23|1,0,0"
        static_ip_request = "24|1,0,0"
        all_requests = [
            mac_info_request, lan_ip_request, dhcp_request, link_type_request, wan_ip_request, static_ip_request]
        request_text = '#'.join(all_requests)
        body = self._encrypt_body(request_text)

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)

        matches = TplinkC80Router.DATA_REGEX.findall(response_text)

        data_blocks = {match[0]: match[1].strip().split("\r\n") for match in matches}

        network_info = {
            'lan_mac': self._extract_value(data_blocks[mac_info_request], "mac 0 "),
            'wan_mac': self._extract_value(data_blocks[mac_info_request], "mac 1 "),
            'lan_ip': self._extract_value(data_blocks[lan_ip_request], "ip "),
            'wan_ip': self._extract_value(data_blocks[wan_ip_request], "ip "),
            'gateway_ip': self._extract_value(data_blocks[wan_ip_request], "gateway "),
            'uptime': self._extract_value(data_blocks[wan_ip_request], "upTime "),
            'wan_mask': self._extract_value(data_blocks[wan_ip_request], "mask "),
            'lan_mask': self._extract_value(data_blocks[lan_ip_request], "mask "),
            'dns_1': self._extract_value(data_blocks[wan_ip_request], "dns 0 "),
            'dns_2': self._extract_value(data_blocks[wan_ip_request], "dns 1 "),
            'dhcp_enabled': self._extract_value(data_blocks[dhcp_request], "enable "),
            'link_type': self._extract_value(data_blocks[link_type_request], "linkType "),
        }

        ipv4status = IPv4Status()
        ipv4status._wan_macaddr = get_mac(network_info['wan_mac'])
        ipv4status._wan_ipv4_ipaddr = get_ip(network_info['wan_ip'])
        ipv4status._wan_ipv4_gateway = get_ip(network_info['gateway_ip'])
        ipv4status._wan_ipv4_conntype = RouterConstants.CONNECTION_TYPE_MAP[network_info['link_type']]
        ipv4status._wan_ipv4_netmask = get_ip(network_info['wan_mask'])
        ipv4status._wan_ipv4_pridns = get_ip(network_info['dns_1'])
        ipv4status._wan_ipv4_snddns = get_ip(network_info['dns_2'])
        ipv4status._lan_macaddr = get_mac(network_info['lan_mac'])
        ipv4status._lan_ipv4_ipaddr = get_ip(network_info['lan_ip'])
        ipv4status.lan_ipv4_dhcp_enable = network_info['dhcp_enabled'] == '1'
        ipv4status._lan_ipv4_netmask = get_ip(network_info['lan_mask'])
        return ipv4status

    def get_ipv4_reservations(self) -> list[IPv4Reservation]:
        body = self._encrypt_body('12|1,0,0')

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)
        matches = TplinkC80Router.DATA_REGEX.findall(response_text)

        data_blocks = {match[0]: match[1].strip().split("\r\n") for match in matches}
        filtered_reservations = self._parse_response_to_dict(data_blocks['12|1,0,0'])

        mapped_reservations: list[IPv4Reservation] = []
        for reservation in filtered_reservations:
            reservation_to_add = IPv4Reservation(get_mac(reservation['mac']), get_ip(reservation['ip']),
                                                 reservation['name'], reservation['dhcpsEnable'] == '1')
            mapped_reservations.append(reservation_to_add)
        return mapped_reservations

    def get_dhcp_leases(self) -> list[IPv4DHCPLease]:
        body = self._encrypt_body('9|1,0,0')

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)
        matches = TplinkC80Router.DATA_REGEX.findall(response_text)

        data_blocks = {match[0]: match[1].strip().split("\r\n") for match in matches}

        filtered_leases = self._parse_response_to_dict(data_blocks['9|1,0,0'])

        mapped_leases: list[IPv4DHCPLease] = []
        for lease in filtered_leases:
            lease_to_add = IPv4DHCPLease(get_mac(lease['mac']), get_ip(lease['ip']),
                                         lease['hostName'], f'expires {lease["expires"]}')
            mapped_leases.append(lease_to_add)

        return mapped_leases

    def get_ipv6_status(self) -> IPv6Status:
        wan_ipv6_request = RouterConstants.IPV6_WAN_REQUEST
        site_ipv6_request = RouterConstants.IPV6_SITE_REQUEST
        all_requests = [
            wan_ipv6_request, site_ipv6_request]
        request_text = '#'.join(all_requests)
        body = self._encrypt_body(request_text)

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)

        matches = TplinkC80Router.DATA_REGEX.findall(response_text)

        data_blocks = {match[0]: match[1].strip().split("\r\n") for match in matches}

        network_info = {
            'wan_ipv6_status': self._extract_value(data_blocks[wan_ipv6_request], "status "),
            'wan_ipv6_getip': self._extract_value(data_blocks[wan_ipv6_request], "getIpWithDhcp "),
            'wan_ipv6_ip': self._extract_value(data_blocks[wan_ipv6_request], "globalIp "),
            'gateway_ipv6': self._extract_value(data_blocks[wan_ipv6_request], "gateway "),
            'dns_1': self._extract_value(data_blocks[wan_ipv6_request], "dns 0 "),
            'dns_2': self._extract_value(data_blocks[wan_ipv6_request], "dns 1 "),
            'site_prefix': self._extract_value(data_blocks[site_ipv6_request], "prefixAddr "),
            'site_prefix_len': self._extract_value(data_blocks[site_ipv6_request], "prefixLen "),
        }

        ipv6status = IPv6Status()
        ipv6status.wan_ipv6_enabled = network_info['wan_ipv6_status'] != '0'
        ipv6status._wan_ipv6_conn_status = RouterConstants.CONNECTION_STATUS_MAP_IPV6.get(
            network_info['wan_ipv6_status'], 'Unknown')
        ipv6status._wan_ipv6_addr_type = RouterConstants.ADDR_TYPE_MAP_IPV6.get(
            network_info['wan_ipv6_getip'], 'Unknown')
        ipv6status._wan_ipv6_addr = get_ipv6(network_info['wan_ipv6_ip'])
        ipv6status._wan_ipv6_gateway = get_ipv6(network_info['gateway_ipv6'])
        ipv6status._wan_ipv6_pridns = get_ipv6(network_info['dns_1'])
        ipv6status._wan_ipv6_snddns = get_ipv6(network_info['dns_2'])
        ipv6status._ipv6_site_prefix = get_ipv6(network_info['site_prefix'])
        ipv6status._ipv6_site_prefix_length = network_info['site_prefix_len']

        return ipv6status

    def get_vpn_status(self) -> VPNStatus:
        body = self._encrypt_body("22|1,0,0")

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)
        matches = TplinkC80Router.DATA_REGEX.findall(response_text)

        data_blocks = {match[0]: match[1].strip().split("\r\n") for match in matches}

        vpn_status = VPNStatus()
        vpn_status.pptpvpn_enable = self._extract_value(data_blocks["22|1,0,0"], "linkType ") == '4'

        return vpn_status

    def _parse_devices(self, device_data_response: list[str]) -> list[Device]:
        filtered_devices = self._parse_response_to_dict(device_data_response)

        device_type_to_connection = {
            0: Connection.WIRED,
            1: Connection.HOST_2G, 2: Connection.GUEST_2G,
            3: Connection.HOST_5G, 4: Connection.GUEST_5G,
            13: Connection.IOT_2G, 14: Connection.IOT_5G
        }

        mapped_devices = []
        for device in filtered_devices:
            if device['online'] == '1':
                device_type = int(device['type'])
                connection_type = device_type_to_connection.get(device_type, Connection.UNKNOWN)
            else:
                connection_type = Connection.UNKNOWN

            device_to_add = Device(connection_type, get_mac(device['mac']), get_ip(device['ip']), device['name'])
            device_to_add.up_speed = int(device['up'])
            device_to_add.down_speed = int(device['down'])
            device_to_add.active = device['online'] == '1'
            mapped_devices.append(device_to_add)
        return mapped_devices

    def _parse_response_to_dict(self, response_data: list[str]) -> list[dict]:
        result_dict = defaultdict(dict)
        for entry in response_data:
            parts = entry.split(' ', 2)
            key, id_str = parts[0], parts[1]
            value = parts[2] if len(parts) == 3 else ''
            result_dict[int(id_str)][key] = value

        return [v for _, v in result_dict.items() if v.get("ip") != "0.0.0.0"]

    @staticmethod
    def _encrypt_password(pwd: str, key: str = RouterConfig.KEY, encoding: str = RouterConfig.ENCODING) -> str:
        max_len = max(len(key), len(pwd))
        pwd = pwd.ljust(max_len, RouterConfig.PAD_CHAR)
        key = key.ljust(max_len, RouterConfig.PAD_CHAR)

        result = []
        for i in range(max_len):
            result.append(encoding[(ord(pwd[i]) ^ ord(key[i])) % len(encoding)])

        return "".join(result)

    @staticmethod
    def _encode_token(encoded_password: str, response: str) -> str:
        response_text = response.text.splitlines()
        auth_info1 = response_text[RouterConstants.AUTH_TOKEN_INDEX1]
        auth_info2 = response_text[RouterConstants.AUTH_TOKEN_INDEX2]

        encoded_token = TplinkC80Router._encrypt_password(encoded_password, auth_info1, auth_info2)
        return parse.quote(encoded_token, safe='!()*')

    def _get_signature(self, datalen: int) -> str:
        encryption = self._encryption
        r = f'{encryption.aes._get_aes_string()}&s={str(int(encryption.seq) + datalen)}'
        e = ''
        n = 0
        while n < len(r):
            e += EncryptionWrapper.rsa_encrypt(r[n:53], encryption.nn_rsa, encryption.ee_rsa)
            n += 53
        return e

    def _encrypt_body(self, text: str) -> str:
        data = self._encryption.aes.aes_encrypt(text)
        sign = self._get_signature(len(data))
        return f'sign={sign}\r\ndata={data}'

    def _decrypt_data(self, encrypted_text: str) -> str:
        if isinstance(encrypted_text, str) and encrypted_text.startswith('00000\r\n'):
            return encrypted_text
        return self._encryption.aes.aes_decrypt(encrypted_text)

    def _extract_value(self, response_list, prefix):
        return next((s.split(prefix, 1)[1] for s in response_list if s.startswith(prefix)), None)

    def _return_data_block(self, request_text: str) -> dict[str, str]:
        body = self._encrypt_body(request_text)

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)

        matches = TplinkC80Router.DATA_REGEX.findall(response_text)

        return {match[0]: match[1].strip().split("\r\n") for match in matches}

    def _parse_last_values_from_block(self, lines: list[str]) -> dict[str, str]:
        values: dict[str, str] = {}
        for line in lines:
            if line == '00000' or line.startswith('id '):
                continue
            key, _, value = line.rpartition(' ')
            if key:
                values[key] = value.strip()
        return values

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

    def _host_ip(self) -> str:
        return urlparse(self.host).hostname or '0.0.0.0'

    def request(self, code: int, asyn: int, use_token: bool = False, data: str = None):
        url = f"{self.host}/?code={code}&asyn={asyn}"
        if use_token:
            url += f"&id={self._encryption.token}"
        try:
            response = self._session.post(url, data=data, timeout=self.timeout, verify=self._session.verify)
            # Raises exception for 4XX/5XX status codes for all requests except 1st in authorize
            if not (code == 2 and asyn == 1 and use_token is False and data is None):
                response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Network error: {e}")
            raise ClientException(f"Network error: {str(e)}") from e
