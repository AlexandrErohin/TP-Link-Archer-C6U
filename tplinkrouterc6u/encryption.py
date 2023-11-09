import base64
from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_v1_5
import binascii
from Crypto.Cipher import AES
from Crypto import Random


class EncryptionWrapper:
    def __init__(self) -> None:
        self.iv = binascii.b2a_hex(Random.get_random_bytes(8))
        self.key = binascii.b2a_hex(Random.get_random_bytes(8))

    def aes_encrypt(self, raw: str) -> str:
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(raw.encode())).decode()

    def aes_decrypt(self, enc: str):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(enc)
        result = self._unpad(decrypted)
        return result.decode()

    def _pad(self, s: str) -> str:
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    def get_aes_string(self) -> str:
        return 'k={}&i={}'.format(self.key.decode(), self.iv.decode())

    @staticmethod
    def rsa_encrypt(data: str, nn: str, ee: str) -> str:
        e = int(ee, 16)
        n = int(nn, 16)

        key = construct((n, e))
        cipher = PKCS1_v1_5.new(key)

        result = cipher.encrypt(data.encode())
        return binascii.b2a_hex(result).decode()

    def get_signature(self, seq: int, is_login: bool, hash: str, nn: str, ee: str) -> str:
        s = ''

        if is_login:
            s = '{}&h={}&s={}'.format(self.get_aes_string(), hash, seq)
        else:
            s = 'h={}&s={}'.format(hash, seq)

        sign = ''
        pos = 0

        while pos < len(s):
            sign = sign + self.rsa_encrypt(s[pos:pos + 53], nn, ee)
            pos = pos + 53

        return sign
