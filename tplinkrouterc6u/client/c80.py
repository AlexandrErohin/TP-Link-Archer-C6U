from dataclasses import dataclass
from logging import Logger
from urllib import parse
from collections import defaultdict
from ipaddress import IPv4Address
import re
from macaddress import EUI48
import requests
from requests import Session
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.dataclass import Firmware, Status, IPv4Status, IPv4Reservation
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


class RouterConfig:
    """Configuration parameters for the router."""
    ENCODING: str = ("yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8"
                     "ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70T"
                     "OoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW")
    KEY: str = "RDpbLfCPsJZ7fiv"
    PAD_CHAR: str = chr(187)


@dataclass
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
        if self._verify_ssl is False:
            self._session.verify = False
        self._encryption = EncryptionState()

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
        body = self._encrypt_body(request_text)

        response = self.request(2, 1, True, data=body)
        response_text = self._decrypt_data(response.text)

        matches = TplinkC80Router.DATA_REGEX.findall(response_text)

        data_blocks = {match[0]: match[1].strip().split("\r\n") for match in matches}

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
        status._wan_macaddr = EUI48(network_info['wan_mac'])
        status._lan_macaddr = EUI48(network_info['lan_mac'])
        status._lan_ipv4_addr = IPv4Address(network_info['lan_ip'])
        status._wan_ipv4_addr = IPv4Address(network_info['wan_ip'])
        status._wan_ipv4_gateway = IPv4Address(network_info['gateway_ip'])
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
        return status

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
        ipv4status._wan_macaddr = EUI48(network_info['wan_mac'])
        ipv4status._wan_ipv4_ipaddr = IPv4Address(network_info['wan_ip'])
        ipv4status._wan_ipv4_gateway = IPv4Address(network_info['gateway_ip'])
        ipv4status._wan_ipv4_conntype = RouterConstants.CONNECTION_TYPE_MAP[network_info['link_type']]
        ipv4status._wan_ipv4_netmask = IPv4Address(network_info['wan_mask'])
        ipv4status._wan_ipv4_pridns = IPv4Address(network_info['dns_1'])
        ipv4status._wan_ipv4_snddns = IPv4Address(network_info['dns_2'])
        ipv4status._lan_macaddr = EUI48(network_info['lan_mac'])
        ipv4status._lan_ipv4_ipaddr = IPv4Address(network_info['lan_ip'])
        ipv4status.lan_ipv4_dhcp_enable = network_info['dhcp_enabled'] == '1'
        ipv4status._lan_ipv4_netmask = IPv4Address(network_info['lan_mask'])
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
            reservation_to_add = IPv4Reservation(EUI48(reservation['mac']), IPv4Address(reservation['ip']),
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
            lease_to_add = IPv4DHCPLease(EUI48(lease['mac']), IPv4Address(lease['ip']),
                                         lease['hostName'], f'expires {lease["expires"]}')
            mapped_leases.append(lease_to_add)

        return mapped_leases

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

            device_to_add = Device(connection_type, EUI48(device['mac']), IPv4Address(device['ip']), device['name'])
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
        return self._encryption.aes.aes_decrypt(encrypted_text)

    def _extract_value(self, response_list, prefix):
        return next((s.split(prefix, 1)[1] for s in response_list if s.startswith(prefix)), None)

    def request(self, code: int, asyn: int, use_token: bool = False, data: str = None):
        url = f"{self.host}/?code={code}&asyn={asyn}"
        if use_token:
            url += f"&id={self._encryption.token}"
        try:
            response = self._session.post(url, data=data, timeout=self.timeout, verify=self._verify_ssl)
            # Raises exception for 4XX/5XX status codes for all requests except 1st in authorize
            if not (code == 2 and asyn == 1 and use_token is False and data is None):
                response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Network error: {e}")
            raise ClientException(f"Network error: {str(e)}") from e
