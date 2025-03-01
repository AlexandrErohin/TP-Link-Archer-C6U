import re
import requests
from dataclasses import dataclass
from requests import Session
from logging import Logger
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.client_abstract import AbstractRouter
from urllib import parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from macaddress import EUI48
from ipaddress import IPv4Address
from collections import defaultdict

class RouterConstants:
    AUTH_TOKEN_INDEX1 = 3
    AUTH_TOKEN_INDEX2 = 4
    DEFAULT_AES_VALUE = "0000000000000000"

    HOST_WIFI_2G_REQUEST = '33|1,1,0'
    HOST_WIFI_5G_REQUEST = '33|2,1,0'
    GUEST_WIFI_2G_REQUEST = '33|1,2,0'
    GUEST_WIFI_5G_REQUEST = '33|2,2,0'
    IOT_WIFI_2G_REQUEST = '33|1,9,0'
    IOT_WIFI_5G_REQUEST = '33|2,9,0'

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
        self.key_aes = ''
        self.iv_aes = ''
        self.aes_string = ''
        self.token = ''

class TplinkC80Router(AbstractRouter):
    DATA_REGEX = re.compile(r'id (\d+\|\d,\d,\d)\r\n(.*?)(?=\r\nid \d+\||$)', re.DOTALL)

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._session = Session()
        self._encryption = EncryptionState()
        self._setup_wifi_requests()
    
    def _setup_wifi_requests(self) -> None:
        self.connection_requests = {
            Connection.HOST_2G: RouterConstants.HOST_WIFI_2G_REQUEST,
            Connection.HOST_5G: RouterConstants.HOST_WIFI_5G_REQUEST,
            Connection.GUEST_2G: RouterConstants.GUEST_WIFI_2G_REQUEST,
            Connection.GUEST_5G: RouterConstants.GUEST_WIFI_5G_REQUEST,
            Connection.IOT_2G: RouterConstants.IOT_WIFI_2G_REQUEST,
            Connection.IOT_5G: RouterConstants.IOT_WIFI_5G_REQUEST
        }

    def supports(self) -> bool:
        response = self.request(2, 1, data='0|1,0,0')
        return 'modelName Archer%20C80' in response.text

    def authorize(self) -> None:
        encodedPassword = TplinkC80Router._encrypt_password(self.password)

        # Get token encryption strings and encrypt the password
        response = self.request(2, 1)
        self._encryption.token = TplinkC80Router._encode_token(encodedPassword, response)

        # Get RSA exponent, modulus and sequence number
        response = self.request(16, 0, data='get')

        responseText = response.text.splitlines()
        if len(responseText) < 4:
            raise ClientException("Invalid response for RSA keys from router")
        self._encryption.ee_rsa = responseText[1]
        self._encryption.nn_rsa = responseText[2]
        self._encryption.seq = responseText[3]

        # Generate key and initialization vector
        self._encryption.key_aes = RouterConstants.DEFAULT_AES_VALUE
        self._encryption.iv_aes = RouterConstants.DEFAULT_AES_VALUE
        self._encryption.aes_string = f'k={self._encryption.key_aes}&i={self._encryption.iv_aes}'

        # Encrypt AES string 
        aes_string_encrypted = EncryptionWrapper.rsa_encrypt(self._encryption.aes_string, self._encryption.nn_rsa, self._encryption.ee_rsa)
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

        return Firmware(parse.unquote(device_datamap['hardVer']), parse.unquote(device_datamap['modelName']), parse.unquote(device_datamap['softVer']))

    def get_status(self) -> Status:
        mac_info_request = "1|1,0,0"
        lan_ip_request = "4|1,0,0"
        wan_ip_request = "23|1,0,0"
        device_data_request = '13|1,0,0'
        all_requests = [
            mac_info_request, lan_ip_request, wan_ip_request, device_data_request,
            RouterConstants.HOST_WIFI_2G_REQUEST, RouterConstants.HOST_WIFI_5G_REQUEST, RouterConstants.GUEST_WIFI_2G_REQUEST, 
            RouterConstants.GUEST_WIFI_5G_REQUEST, RouterConstants.IOT_WIFI_2G_REQUEST, RouterConstants.IOT_WIFI_5G_REQUEST
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
        
        wifi_mappings = {
            'host_2g': RouterConstants.HOST_WIFI_2G_REQUEST,
            'host_5g': RouterConstants.HOST_WIFI_5G_REQUEST,
            'guest_2g': RouterConstants.GUEST_WIFI_2G_REQUEST,
            'guest_5g': RouterConstants.GUEST_WIFI_5G_REQUEST,
            'iot_2g': RouterConstants.IOT_WIFI_2G_REQUEST,
            'iot_5g': RouterConstants.IOT_WIFI_5G_REQUEST
        }

        wifi_status = {key: extract_value(data_blocks[request], "bEnable ") == '1'
                  for key, request in wifi_mappings.items()}

        device_data_response = data_blocks[device_data_request]

        mapped_devices = self._parse_devices(device_data_response)
        
        status = Status()
        status._wan_macaddr = EUI48(network_info['wan_mac'])
        status._lan_macaddr = EUI48(network_info['lan_mac'])
        status._lan_ipv4_addr = IPv4Address(network_info['lan_ip'])
        status._wan_ipv4_addr = IPv4Address(network_info['wan_ip'])
        status._wan_ipv4_gateway = IPv4Address(network_info['gateway_ip'])
        status.wan_ipv4_uptime = int(network_info['uptime']) // 100
        
        status.wifi_2g_enable = wifi_status['host_2g']
        status.wifi_5g_enable = wifi_status['host_5g']
        status.guest_2g_enable = wifi_status['guest_2g']
        status.guest_5g_enable = wifi_status['guest_5g']
        status.iot_2g_enable = wifi_status['iot_2g']
        status.iot_5g_enable = wifi_status['iot_5g']
        
        status.wired_total = sum(1 for device in mapped_devices if device.type == Connection.WIRED)
        status.wifi_clients_total = sum(1 for device in mapped_devices if device.type in (Connection.HOST_2G, Connection.HOST_5G))
        status.guest_clients_total = sum(1 for device in mapped_devices if device.type in (Connection.GUEST_2G, Connection.GUEST_5G))
        status.iot_clients_total = sum(1 for device in mapped_devices if device.type in (Connection.IOT_2G, Connection.IOT_5G))
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total + status.iot_clients_total
        
        status.devices = mapped_devices
        return status

    def reboot(self) -> None:
        self.request(6, 1, True)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        enable_string = f'bEnable {int(enable)}'
        text = f'id {self.connection_requests[wifi]}\r\n{enable_string}'
        body = self._encrypt_body(text)
        self.request(1, 0, True, data=body)

    def _parse_devices(self, device_data_response: list[str]) -> list[Device]:
        device_dict = defaultdict(dict)
        for entry in device_data_response:
            entry_list = entry.split(' ', 2)
            device_dict[int(entry_list[1])][entry_list[0]] = entry_list[2]  # Grouping by device ID

        filtered_devices = [v for _, v in device_dict.items() if v.get("ip") != "0.0.0.0"]

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
                device['tag'] = connection_type
            else:
                device['tag'] = Connection.UNKNOWN
            
            device_to_add = Device(device['tag'], EUI48(device['mac']), IPv4Address(device['ip']), device['name'])
            device_to_add.up_speed = int(device['up'])
            device_to_add.down_speed = int(device['down'])
            mapped_devices.append(device_to_add)
        return mapped_devices

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
    def _encode_token(encodedPassword: str, response: str) -> str:
        responseText = response.text.splitlines()
        authInfo1 = responseText[RouterConstants.AUTH_TOKEN_INDEX1]
        authInfo2 = responseText[RouterConstants.AUTH_TOKEN_INDEX2]

        encodedToken = TplinkC80Router._encrypt_password(encodedPassword, authInfo1, authInfo2)
        return parse.quote(encodedToken, safe='!()*')
    
    def _get_signature(self, datalen: int) -> str:
        encryption = self._encryption
        r = f'{encryption.aes_string}&s={str(int(encryption.seq) + datalen)}'
        e = ''
        n = 0
        while n < len(r):
            e += EncryptionWrapper.rsa_encrypt(r[n:53], encryption.nn_rsa, encryption.ee_rsa)
            n += 53
        return e
    
    def _encrypt_body(self, text: str) -> str:
        encryption = self._encryption

        key_bytes = encryption.key_aes.encode("utf-8")
        iv_bytes = encryption.iv_aes.encode("utf-8")

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        data = b64encode(cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))).decode()

        sign = self._get_signature(len(data))
        return f'sign={sign}\r\ndata={data}'
    
    def _decrypt_data(self, encrypted_text: str) -> str:
        key_bytes = self._encryption.key_aes.encode("utf-8")
        iv_bytes = self._encryption.iv_aes.encode("utf-8")

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(b64decode(encrypted_text))
        return unpad(decrypted_padded, AES.block_size).decode("utf-8")
   
    def request(self, code: int, asyn: int, use_token: bool = False, data: str = None):
        url = f"{self.host}/?code={code}&asyn={asyn}"
        if use_token:
            url += f"&id={self._encryption.token}"
        try:
            response = self._session.post(url, data=data, timeout=self.timeout)
            # Raises exception for 4XX/5XX status codes for all requests except 1st in authorize
            if not (code == 2 and asyn == 1 and use_token is False and data is None):
                response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Network error: {e}")
            raise ClientException(f"Network error: {str(e)}")
        
# TODO add crypto class - extract common encryption object