import logging
import re
import json
import random
import hashlib
import requests
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Import ufficiali allineati alla struttura reale del pacchetto
from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.exception import ClientException

_LOGGER = logging.getLogger(__name__)

class TplinkVR1200vRouter(AbstractRouter):
    """Specific API Client for TP-Link Archer VR1200v with encrypted GDPR firmware."""

    def __init__(self, host, password, username="user", logger=None, verify_ssl=True, timeout=30):
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self.ip = re.sub(r'^https?://', '', self.host).split(':')[0]
        
        # Cryptographic state and hardware session data
        self.aes_key = None
        self.aes_iv = None
        self.ee = None
        self.nn = None
        self.seq = None
        self.md5_signature = None
        self.is_authorized = False
        
        # Login strictly starts with TokenID "0". It becomes dynamic post-login.
        self.token_id = "0"
        self._session = requests.Session()
        self._session.verify = self._verify_ssl

    def _gen_random_numeric_string(self, length):
        """Generate random numeric strings required by the firmware."""
        return "".join(random.choice("0123456789") for _ in range(length))

    def _encrypt_rsa(self, modulus_hex, exponent_hex, plaintext_bytes):
        """Encrypt the signature using RSA, returning a 128-character lowercase hex string."""
        n = int(modulus_hex, 16)
        e = int(exponent_hex, 16)
        
        step = 64
        encrypted_blocks = []
        
        for i in range(0, len(plaintext_bytes), step):
            chunk = plaintext_bytes[i:i+step]
            if len(chunk) < step:
                chunk = chunk + b'\x00' * (step - len(chunk))
                
            m_int = int.from_bytes(chunk, byteorder='big')
            c_int = pow(m_int, e, n)
            encrypted_blocks.append(f"{c_int:0128x}")
            
        return "".join(encrypted_blocks)

    def _parse_js_response(self, js_text):
        """Convert JavaScript variable assignments or JSON into a Python dictionary."""
        parsed_data = {}
        
        if js_text.strip().startswith('{') and js_text.strip().endswith('}'):
            try:
                return json.loads(js_text)
            except Exception:
                pass

        matches = re.findall(r'(?:var\s+)?([\w_]+)\s*=\s*(["\'].*?["\']|\[.*?\]|[\d\.]+);', js_text)
        for key, value in matches:
            clean_val = value.strip('"\'')
            if clean_val.startswith('[') and clean_val.endswith(']'):
                try:
                    clean_val = json.loads(clean_val.replace("'", '"'))
                except Exception:
                    pass
            parsed_data[key] = clean_val
        return parsed_data

    def fetch_handshake_params(self):
        """Perform HTTP pre-handshake to retrieve RSA keys and initial sequence ID."""
        url = f"http://{self.ip}/cgi/getGDPRParm"
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"http://{self.ip}/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0",
            "Connection": "keep-alive"
        }
        
        try:
            response = self._session.post(url, data=None, headers=headers, timeout=self.timeout)
            js_code = response.text
            
            ee = re.search(r'ee\s*=\s*"([^"]+)"', js_code)
            nn = re.search(r'nn\s*=\s*"([^"]+)"', js_code)
            seq = re.search(r'seq\s*=\s*"([^"]+)"', js_code)
            
            if not ee or not nn or not seq:
                raise ClientException("Failed to find cryptographic parameters during handshake.")
                
            return ee.group(1), nn.group(1), int(seq.group(1))
        except Exception as e:
            raise ClientException(f"Connection failed during handshake: {e}")

    def authorize(self):
        """Establish an encrypted authenticated session on the router."""
        self.ee, self.nn, self.seq = self.fetch_handshake_params()
        
        self.aes_key = self._gen_random_numeric_string(16)
        self.aes_iv = self._gen_random_numeric_string(16)
        
        username = "user" if (not self.username or self.username == "admin") else self.username
        self.md5_signature = hashlib.md5(f"{username}{self.password}".encode('utf-8')).hexdigest()
        
        username_b64 = b64encode(username.encode('utf-8')).decode('utf-8')
        password_b64 = b64encode(self.password.encode('utf-8')).decode('utf-8')
        
        login_payload = {
            "operation": "cgi",
            "oid": "/cgi/login",
            "data": {
                "UserName": username_b64,
                "Passwd": password_b64,
                "Action": "1",
                "stack": "0,0,0,0,0,0",
                "pstack": "0,0,0,0,0,0"
            }
        }
        
        response = self._send_packet(login_payload, is_login=True)
        if "$.ret=0;" in response or '"ret":0' in response:
            self.is_authorized = True
            
            # Immediately after login, a GET / request is needed to receive the TokenID from the HTML response
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0",
                "Referer": f"http://{self.ip}/"
            }
            res_get = self._session.get(f"http://{self.ip}/", headers=headers, timeout=self.timeout)
            token_match = re.search(r'var token="([^"]+)"', res_get.text)
            if token_match:
                self.token_id = token_match.group(1)
                
                # CRITICAL: The router recalculates the RSA signature hash using MD5(username + token) 
                # for all queries subsequent to login!
                username = "user" if (not self.username or self.username == "admin") else self.username
                self.md5_signature = hashlib.md5(f"{username}{self.token_id}".encode('utf-8')).hexdigest()
            
            return True
        
        raise ClientException(f"VR1200v authentication failed: {response}")

    def _send_packet(self, payload_obj, is_login=False):
        """Send an encrypted JSON payload block via requests."""
        # The VR1200v firmware expects a bare JSON object, without array wrapping
        plaintext_json = json.dumps(payload_obj, separators=(',', ':'))
        cipher_aes = AES.new(self.aes_key.encode('utf-8'), AES.MODE_CBC, self.aes_iv.encode('utf-8'))
        padded_data = pad(plaintext_json.encode('utf-8'), AES.block_size, style='pkcs7')
        encrypted_bytes = cipher_aes.encrypt(padded_data)
            
        aes_data_b64 = b64encode(encrypted_bytes).decode('utf-8')
        
        # The frontend JS does NOT increment this.seq in memory for subsequent calls.
        # It simply uses initial seq + dataLen for the signature.
        current_seq = self.seq + len(aes_data_b64)
        
        if is_login:
            sign_string = f"key={self.aes_key}&iv={self.aes_iv}&h={self.md5_signature}&s={current_seq}"
        else:
            sign_string = f"h={self.md5_signature}&s={current_seq}"
            
        rsa_sign_hex = self._encrypt_rsa(self.nn, self.ee, sign_string.encode('utf-8'))
        
        # Strictly no trailing or leading \r\n in the overall string boundaries
        payload_post = f"sign={rsa_sign_hex}\r\ndata={aes_data_b64}\r\n"
        
        headers = {
            "Content-Type": "text/plain",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "TokenID": self.token_id,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0",
            "Referer": f"http://{self.ip}/"
        }
        
        url = f"http://{self.ip}/cgi_gdpr?9"
        res = self._session.post(url, headers=headers, data=payload_post, timeout=self.timeout)
        
        if res.status_code != 200:
            raise ClientException(f"Request failed with HTTP {res.status_code}: {res.text}")
            
        body = res.text
        b64_match = re.search(r'([a-zA-Z0-9+/=]{15,})', body)
        if not b64_match:
            return body
            
        encrypted_b64 = b64_match.group(1)
        cipher_decrypt = AES.new(self.aes_key.encode('utf-8'), AES.MODE_CBC, self.aes_iv.encode('utf-8'))
        decrypted_raw = cipher_decrypt.decrypt(b64decode(encrypted_b64))
        decrypted_text = unpad(decrypted_raw, AES.block_size, style='pkcs7').decode('utf-8')
        
        return decrypted_text

    def _query(self, operation, oid, custom_fields=None):
        """Helper method to send standard post-login queries."""
        data_block = {"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}
        if custom_fields:
            data_block.update(custom_fields)

        payload = {
            "data": data_block,
            "operation": operation,
            "oid": oid
        }
        raw_res = self._send_packet(payload, is_login=False)
        return self._parse_js_response(raw_res)

    # --- PUBLIC METHODS COMPATIBLE WITH HOME ASSISTANT ---

    def supports(self) -> bool:
        return True

    def get_firmware(self):
        if not self.is_authorized:
            self.authorize()
        info = self._query("go", "DEV2_DEV_INFO", {"description": ""})
        return {
            "hardware_version": "Archer VR1200v",
            "firmware_version": info.get("description", "GDPR Firmware Native")
        }

    def get_status(self):
        if not self.is_authorized:
            self.authorize()
            
        info = self._query("go", "DEV2_DEV_INFO", {"upTime": ""})
        mem = self._query("go", "DEV2_MEM_STATUS", {"total": "", "free": ""})
        proc = self._query("go", "DEV2_PROC_STATUS", {"CPUUsage": ""})
        wan = self._query("gl", "DEV2_ADT_WAN")
        
        info_data = info.get("data", {})
        mem_data = mem.get("data", {})
        proc_data = proc.get("data", {})
        
        wan_list = wan.get("data", [])
        wan_ip = "Unknown"
        if isinstance(wan_list, list) and len(wan_list) > 0:
            wan_ip = wan_list[0].get("IPAddress", "Unknown")
        elif isinstance(wan_list, dict):
            wan_ip = wan_list.get("IPAddress", "Unknown")
        
        return {
            "model": "Archer VR1200v",
            "uptime": info_data.get("upTime", "Unknown"),
            "cpu_usage": proc_data.get("CPUUsage", "Unknown"),
            "memory_total": mem_data.get("total", "Unknown"),
            "memory_free": mem_data.get("free", "Unknown"),
            "wan_ip": wan_ip
        }

    def get_ipv4_status(self):
        if not self.is_authorized:
            self.authorize()
        return self._query("gl", "DEV2_ADT_WAN")

    def get_devices(self):
        if not self.is_authorized:
            self.authorize()
            
        self._query("op", "ACT_UPDATE_MAPINFO")
        wifi_devs = self._query("gl", "DEV2_WIFI_APDEV_ASSOCDEV")
        eth_devs = self._query("gl", "DEV2_WIFI_APDEV_ETHASSOCDEV")
        
        return {
            "wifi_raw": wifi_devs,
            "eth_raw": eth_devs
        }

    def logout(self):
        self.is_authorized = False
        self.token_id = "0"
        self._session.cookies.clear()
        return True

    def reboot(self):
        if not self.is_authorized:
            self.authorize()
        reboot_payload = {
            "operation": "cgi",
            "oid": "/cgi/reboot",
            "data": {"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}
        }
        self._send_packet(reboot_payload, is_login=False)

    def set_wifi(self, *args, **kwargs):
        pass