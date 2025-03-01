import re
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


# code 2 asyn 1 - 401 error and strings for encrypting password
# code 16 asyn 0 gives seq, AES nn and e values
# code 7 asyn 0 with id gives 00000 as ack i think
# code 16 asyn 0 with id sets AES keys for router to use

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
        self.key_aes = ''
        self.iv_aes = ''
        self.string_aes = ''
        self.token = ''

class TplinkC80Router(AbstractRouter):

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._session = Session()
        self._encryption = EncryptionWrapper()
        self._encryption_state = EncryptionState()
        self._setup_wifi_requests()
    
    def _setup_wifi_requests(self) -> None:
        """Initialize WiFi request mappings."""
        self.host_wifi_2g_request = '33|1,1,0'
        self.host_wifi_5g_request = '33|2,1,0'
        self.guest_wifi_2g_request = '33|1,2,0'
        self.guest_wifi_5g_request = '33|2,2,0'
        self.iot_wifi_2g_request = '33|1,9,0'
        self.iot_wifi_5g_request = '33|2,9,0'

        self.connection_requests = {
            Connection.HOST_2G: self.host_wifi_2g_request,
            Connection.HOST_5G: self.host_wifi_5g_request,
            Connection.GUEST_2G: self.guest_wifi_2g_request,
            Connection.GUEST_5G: self.guest_wifi_5g_request,
            Connection.IOT_2G: self.iot_wifi_2g_request,
            Connection.IOT_5G: self.iot_wifi_5g_request
        }

    def supports(self) -> bool:
        response = self.request(2, 1, data='0|1,0,0')
        return 'modelName Archer%20C80' in response.text

    def authorize(self) -> None:
        encodedPassword = self._encrypt(self.password)

        # Get token encryption strings and encrypt the password
        response = self.request(2, 1)
        self._encryption_state.token = TplinkC80Router._encode_token(encodedPassword, response)

        # Get RSA exponent, modulus and sequence number
        response = self.request(16, 0, data='get')

        responseText = response.text.splitlines()
        if len(responseText) < 4:
            raise ClientException("Invalid response for RSA keys from router")
        self._encryption_state.ee_rsa = responseText[1]
        self._encryption_state.nn_rsa = responseText[2]
        self._encryption_state.seq = responseText[3]

        # Generate key and initialization vector
        self._encryption_state.key_aes = "0000000000000000"
        self._encryption_state.iv_aes = "0000000000000000"
        self._encryption_state.string_aes = f'k={self._encryption_state.key_aes}&i={self._encryption_state.iv_aes}'

        # Encrypt AES string 
        aes_string_encrypted = EncryptionWrapper.rsa_encrypt(self._encryption_state.string_aes, self._encryption_state.nn_rsa, self._encryption_state.ee_rsa)
        # Register AES string for decryption on server side
        self.request(16, 0, self._encryption_state.token, data='set ' + aes_string_encrypted)
        # Some auth request, might be redundant
        response = self.request(7, 0, self._encryption_state.token)

    def logout(self) -> None:
        self.request(11, 0, self._encryption_state.token)

    def get_firmware(self) -> Firmware:
        text = '0|1,0,0'
        
        body = self._encrypt_body(self._encryption_state.key_aes, self._encryption_state.iv_aes, self._encryption_state.string_aes, text, 
                                        self._encryption_state.seq, self._encryption_state.nn_rsa, self._encryption_state.ee_rsa)

        response = self.request(2, 1, self._encryption_state.token, data = body)
        response_text = self._decrypt_data(self._encryption_state.key_aes, self._encryption_state.iv_aes, response.text)
        device_datamap = dict(line.split(" ", 1) for line in response_text.split("\r\n")[1:-1])

        return Firmware(parse.unquote(device_datamap['hardVer']), parse.unquote(device_datamap['modelName']), parse.unquote(device_datamap['softVer']))

    def get_status(self) -> Status:
        mac_info_request = "1|1,0,0"
        lan_ip_request = "4|1,0,0"
        wan_ip_request = "23|1,0,0"
        device_data_request = '13|1,0,0'
        request_text = '#'.join([mac_info_request, lan_ip_request, wan_ip_request, device_data_request,
                                 self.host_wifi_2g_request, self.host_wifi_5g_request, self.guest_wifi_2g_request, 
                                 self.guest_wifi_5g_request, self.iot_wifi_2g_request, self.iot_wifi_5g_request])
        body = self._encrypt_body(self._encryption_state.key_aes, self._encryption_state.iv_aes, self._encryption_state.string_aes, request_text, 
                                        self._encryption_state.seq, self._encryption_state.nn_rsa, self._encryption_state.ee_rsa)

        response = self.request(2, 1, self._encryption_state.token, data = body)
        response_text = self._decrypt_data(self._encryption_state.key_aes, self._encryption_state.iv_aes, response.text)
        
        matches = re.findall(r'id (\d+\|\d,\d,\d)\r\n(.*?)(?=\r\nid \d+\||$)', response_text, re.DOTALL)

        data_blocks = {match[0]: match[1].strip().split("\r\n") for match in matches}

        mac_info_response = data_blocks[mac_info_request]
        lan_ip_response = data_blocks[lan_ip_request]
        wan_ip_response = data_blocks[wan_ip_request]
        device_data_response = data_blocks[device_data_request]
        
        host_wifi_2g_response = data_blocks[self.host_wifi_2g_request]
        host_wifi_5g_response = data_blocks[self.host_wifi_5g_request]
        guest_wifi_2g_response = data_blocks[self.guest_wifi_2g_request]
        guest_wifi_5g_response = data_blocks[self.guest_wifi_5g_request]
        iot_wifi_2g_response = data_blocks[self.iot_wifi_2g_request]
        iot_wifi_5g_response = data_blocks[self.iot_wifi_5g_request]

        lan_mac = next(s.split("mac 0 ", 1)[1] for s in mac_info_response if s.startswith("mac 0 "))
        wan_mac = next(s.split("mac 1 ", 1)[1] for s in mac_info_response if s.startswith("mac 1 "))

        lan_ip = next(s.split("ip ", 1)[1] for s in lan_ip_response if s.startswith("ip "))

        wan_ip = next(s.split("ip ", 1)[1] for s in wan_ip_response if s.startswith("ip "))
        gateway_ip = next(s.split("gateway ", 1)[1] for s in wan_ip_response if s.startswith("gateway "))
        uptime = next(s.split("upTime ", 1)[1] for s in wan_ip_response if s.startswith("upTime "))

        host_wifi_2g = next(s.split("bEnable ", 1)[1] for s in host_wifi_2g_response if s.startswith("bEnable "))
        host_wifi_5g = next(s.split("bEnable ", 1)[1] for s in host_wifi_5g_response if s.startswith("bEnable "))
        guest_wifi_2g = next(s.split("bEnable ", 1)[1] for s in guest_wifi_2g_response if s.startswith("bEnable "))
        guest_wifi_5g = next(s.split("bEnable ", 1)[1] for s in guest_wifi_5g_response if s.startswith("bEnable "))
        iot_wifi_2g = next(s.split("bEnable ", 1)[1] for s in iot_wifi_2g_response if s.startswith("bEnable "))
        iot_wifi_5g = next(s.split("bEnable ", 1)[1] for s in iot_wifi_5g_response if s.startswith("bEnable "))

        device_dict = defaultdict(dict)
        for entry in device_data_response:
            entry_list = entry.split(' ', 2)
            device_dict[int(entry_list[1])][entry_list[0]] = entry_list[2]  # Grouping by device ID

        filtered_devices = [v for _, v in device_dict.items() if v.get("ip") != "0.0.0.0"]

        mapped_devices: list[Device] = []
        for device in filtered_devices:
            if device['online'] == '1':
                device_tags = {0: Connection.WIRED, 1: Connection.HOST_2G, 2: Connection.GUEST_2G, 
                               3: Connection.HOST_5G, 4: Connection.GUEST_5G, 13: Connection.IOT_2G, 14: Connection.IOT_5G}
                device['tag'] = device_tags[int(device['type'])]
            else:
                device['tag'] = Connection.UNKNOWN
            
            device_to_add = Device(device['tag'], EUI48(device['mac']), IPv4Address(device['ip']), device['name'])
            device_to_add.up_speed = int(device['up'])
            device_to_add.down_speed = int(device['down'])
            mapped_devices.append(device_to_add)
        
        status = Status()
        status._wan_macaddr = EUI48(wan_mac)
        status._lan_macaddr = EUI48(lan_mac)
        status._lan_ipv4_addr = IPv4Address(lan_ip)
        status._wan_ipv4_addr = IPv4Address(wan_ip)
        status._wan_ipv4_gateway = IPv4Address(gateway_ip)
        status.wired_total = sum(1 for device in mapped_devices if device.type == Connection.WIRED)
        status.wifi_clients_total = sum(1 for device in mapped_devices if device.type in (Connection.HOST_2G, Connection.HOST_5G))
        status.guest_clients_total = sum(1 for device in mapped_devices if device.type in (Connection.GUEST_2G, Connection.GUEST_5G))
        status.iot_clients_total = sum(1 for device in mapped_devices if device.type in (Connection.IOT_2G, Connection.IOT_5G))
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total + status.iot_clients_total
        status.wifi_2g_enable = host_wifi_2g == '1'
        status.wifi_5g_enable = host_wifi_5g == '1'
        status.guest_2g_enable = guest_wifi_2g == '1'
        status.guest_5g_enable = guest_wifi_5g == '1'
        status.iot_2g_enable = iot_wifi_2g == '1'
        status.iot_5g_enable = iot_wifi_5g == '1'

        status.wan_ipv4_uptime = int(uptime) // 100
        status.devices = mapped_devices

        return status

    def reboot(self) -> None:
        self.request(6, 1, self._encryption_state.token)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        enable_string = f'bEnable {int(enable)}'
        text = f'id {self.connection_requests[wifi]}\r\n{enable_string}'
        body = self._encrypt_body(self._encryption_state.key_aes, self._encryption_state.iv_aes, self._encryption_state.string_aes, text, 
                                        self._encryption_state.seq, self._encryption_state.nn_rsa, self._encryption_state.ee_rsa)
        self.request(1, 0, self._encryption_state.token, data=body)

    @staticmethod
    def _encrypt(pwd: str, key: str = RouterConfig.KEY, encoding: str = RouterConfig.ENCODING) -> str:
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
        authInfo1 = responseText[3]
        authInfo2 = responseText[4]

        encodedToken = TplinkC80Router._encrypt(authInfo1, encodedPassword, authInfo2)
        return parse.quote(encodedToken, safe='!()*')
    
    def _get_signature(self, aes_key_string: str, seq: str, nn: str, ee: str) -> str:
        r = aes_key_string + "&s=" + str(seq)
        e = ""
        n = 0
        while n < len(r):
            e += EncryptionWrapper.rsa_encrypt(r[n:53], nn, ee)
            n += 53
        return e
    
    def _encrypt_body(self, key: str, iv: str, aes_string: str, text: str, seq: str, nn: str, ee: str) -> str:
        key_bytes = key.encode("utf-8")
        iv_bytes = iv.encode("utf-8")

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        data = b64encode(cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))).decode()

        sign = self._get_signature(aes_string, int(seq) + len(data), nn, ee)
        return f'sign={sign}\r\ndata={data}'
    
    def _decrypt_data(self, key: str, iv: str, encrypted_text: str) -> str:
        key_bytes = key.encode("utf-8")
        iv_bytes = iv.encode("utf-8")

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(b64decode(encrypted_text))
        return unpad(decrypted_padded, AES.block_size).decode("utf-8")
   
    def request(self, code: int, asyn: int, token: str = None, data: str = None):
        url = f"{self.host}/?code={code}&asyn={asyn}"
        if token:
            url += f"&id={token}"
        return self._session.post(url, data=data)