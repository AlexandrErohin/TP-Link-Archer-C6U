from requests import Session
from logging import Logger
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client_abstract import AbstractRouter
from urllib import parse
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


# code 2 asyn 1 - 401 error and strings for encrypting password
# code 16 asyn 0 gives seq, AES nn and e values
# code 7 asyn 0 with id gives 00000 as ack i think
# code 16 asyn 0 with id sets AES keys for router to use

class TplinkC80Router(AbstractRouter):
    ENCODING = ("yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8"
                   "ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70T"
                   "OoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW")
    KEY = "RDpbLfCPsJZ7fiv"
    PAD_CHAR = chr(187)

    nnRSA = ''
    eeRSA = ''
    seq = ''

    keyAES = ''
    ivAES = ''
    stringAES = ''

    token = ''
    _encryption = EncryptionWrapper()
   
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._session = Session()

    def supports(self) -> bool:
        url = '{}/?code=2&asyn=1'.format(self.host)
        response = self._session.post(url, data='0|1,0,0')
        return 'modelName Archer%20C80' in response.text

    def authorize(self) -> None:
        authInfoUrl = self._build_url(2, 1)
        RSAKeyUrl = self._build_url(16, 0)
        
        encodedPassword = self._encrypt(self.password)

        # Get token encryption strings and encrypt the password
        response = self._session.post(authInfoUrl)
        TplinkC80Router.token = TplinkC80Router._encode_token(encodedPassword, response)

        # Get RSA exponent, modulus and sequence number
        response = self._session.post(RSAKeyUrl, data='get')
        self._handle_error(response)

        responseText = response.text.splitlines()
        TplinkC80Router.eeRSA = responseText[1]
        TplinkC80Router.nnRSA = responseText[2]
        TplinkC80Router.seq = responseText[3]

        # Generate key and initialization vector
        TplinkC80Router.keyAES = "0000000000000000"
        TplinkC80Router.ivAES = "0000000000000000"
        TplinkC80Router.stringAES = f'k={TplinkC80Router.keyAES}&i={TplinkC80Router.ivAES}'

        # Encrypt AES string 
        aes_string_encrypted = EncryptionWrapper.rsa_encrypt(TplinkC80Router.stringAES, TplinkC80Router.nnRSA, TplinkC80Router.eeRSA)
        # Sync AES string for decryption on server side
        response = self._session.post(self._build_url(16, 0, TplinkC80Router.token), data='set ' + aes_string_encrypted)
        self._handle_error(response)
        
        response = self._session.post(self._build_url(7, 0, TplinkC80Router.token))
        self._handle_error(response)

        self.get_devices()
        print(self.get_firmware())

        try:
            # print(response.status_code)
            print(response.text)
        except Exception as e:
            error = ('TplinkRouter - {} - Cannot authorize! Error - {}; Response - {}'.
                     format(self.__class__.__name__, e, response))
            raise ClientException(error)

    def logout(self) -> None:
        logoutUrl = lambda token : '{}/?code=11&asyn=0&id={}'.format(self.host, token)
        response = self._session.post(logoutUrl(TplinkC80Router.token))
        self._handle_error(response)

    def get_firmware(self) -> Firmware:
        text = '0|1,0,0'
        
        sign, data = self._encrypt_data(TplinkC80Router.keyAES, TplinkC80Router.ivAES, TplinkC80Router.stringAES, text, 
                                        TplinkC80Router.seq, TplinkC80Router.nnRSA, TplinkC80Router.eeRSA)

        body = f'sign={sign}\r\ndata={data}'

        response = self._session.post('{}/?code=2&asyn=1&id={}'.format(self.host, TplinkC80Router.token), data = body)
        response_text = self._decrypt_data(TplinkC80Router.keyAES, TplinkC80Router.ivAES, response.text)
        device_datamap = dict(line.split(" ", 1) for line in response_text.split("\r\n")[1:-1])

        return Firmware(parse.unquote(device_datamap.get('hardVer')), parse.unquote(device_datamap.get('modelName')), parse.unquote(device_datamap.get('hardVer')))

    def get_status(self) -> Status:
        raise ClientException('Not Implemented')

    def reboot(self) -> None:
        raise ClientException('Not Implemented')

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        raise ClientException('Not Implemented')
    
    def get_devices(self):
        text = '13|1,0,0'
        sign, data = self._encrypt_data(TplinkC80Router.keyAES, TplinkC80Router.ivAES, TplinkC80Router.stringAES, text, 
                                        TplinkC80Router.seq, TplinkC80Router.nnRSA, TplinkC80Router.eeRSA)

        body = f'sign={sign}\r\ndata={data}'
        response = self._session.post('{}/?code=2&asyn=1&id={}'.format(self.host, TplinkC80Router.token), data=body)
        response_text = self._decrypt_data(TplinkC80Router.keyAES, TplinkC80Router.ivAES, response.text)

        result = []
        online_devices = []
        for line in response_text.split('\r\n'):
            parts = line.split(' ')
            if parts[0] == "name" and len(parts) > 2 and parts[2]:  # ensure name exists
                result.append((parts[1], parts[2]))
            
            if parts[0] == "online" and parts[2] == '1':  # ensure name exists
                online_devices.append(parts[1])
            
        for id, name in result:
            if id in online_devices:
                print(f"{id} {name} online")
            else:
                print(f"{id} {name}")


    @staticmethod
    def _encrypt(pwd, key: str = KEY, encoding: str = ENCODING):
        max_len = max(len(key), len(pwd))

        pwd = pwd.ljust(max_len, TplinkC80Router.PAD_CHAR)
        key = key.ljust(max_len, TplinkC80Router.PAD_CHAR)

        result = []

        for i in range(max_len):
            result.append(encoding[(ord(pwd[i]) ^ ord(key[i])) % len(encoding)])
        
        return "".join(result)
    
    @staticmethod
    def _encode_token(encodedPassword: str, response: str):
        responseText = response.text.splitlines()
        authInfo1 = responseText[3]
        authInfo2 = responseText[4]

        encodedToken = TplinkC80Router._encrypt(authInfo1, encodedPassword, authInfo2)
        return parse.quote(encodedToken, safe='!()*')
    
    def _get_signature(self, aes_key_string, seq, nn, ee):
        r = aes_key_string + "&s=" + str(seq)
        e = ""
        n = 0
        while n < len(r):
            e += EncryptionWrapper.rsa_encrypt(r[n:53], nn, ee)
            n += 53
        return e
    
    def _encrypt_data(self, key, iv, aes_string, text, seq, nn, ee):
        key_bytes = key.encode("utf-8")
        iv_bytes = iv.encode("utf-8")

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        data = b64encode(cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))).decode()

        sign = self._get_signature(aes_string, int(seq) + len(data), nn, ee)
        return sign, data
    
    def _decrypt_data(self, key, iv, encrypted_text):
        key_bytes = key.encode("utf-8")
        iv_bytes = iv.encode("utf-8")

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(b64decode(encrypted_text))  # Decode base64 first
        decrypted_text = unpad(decrypted_padded, AES.block_size).decode("utf-8")  # Unpad correctly

        return decrypted_text
    
    def _handle_error(self, response):
        if response.text == '00006':
            error = ('TplinkRouter - {} - Cannot authorize! Error - {}'.
                     format(self.__class__.__name__, 'Failed to set router AES keys ("Prohibited operation")'))
            raise ClientException(error)
        
    def _build_url(self, code: int, asyn: int, token: str = None) -> str:
        url = f"{self.host}/?code={code}&asyn={asyn}"
        if token:
            url += f"&id={token}"
        return url