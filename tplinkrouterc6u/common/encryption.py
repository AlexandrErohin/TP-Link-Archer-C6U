from base64 import b64encode, b64decode
from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_v1_5
from binascii import b2a_hex, hexlify
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from time import time
from random import randint
from Crypto.PublicKey.ECC import EccPoint, _curves as _ecc_curves
from Crypto.Hash import SHA256 as CryptoSHA256, HMAC as CryptoHMAC
from json import dumps as json_dumps


class EncryptionWrapper:
    def __init__(self) -> None:
        self._iv = b2a_hex(Random.get_random_bytes(8))
        self._key = b2a_hex(Random.get_random_bytes(8))

    def aes_encrypt(self, raw: str) -> str:
        raw = self._pad(raw)
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        return b64encode(cipher.encrypt(raw.encode())).decode()

    def aes_decrypt(self, enc: str):
        enc = b64decode(enc)
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        decrypted = cipher.decrypt(enc)
        result = self._unpad(decrypted)
        # The decrypted payload may contain invalid UTF-8 bytes (e.g. garbage
        # in a device nickname from the Deco app, see HA #374). Ignoring them
        # lets the surrounding JSON parse instead of crashing the whole setup.
        return result.decode('utf-8', errors='ignore')

    @staticmethod
    def rsa_encrypt(data: str, nn: str, ee: str) -> str:
        e = int(ee, 16)
        n = int(nn, 16)

        key = construct((n, e))
        cipher = PKCS1_v1_5.new(key)

        result = cipher.encrypt(data.encode())
        return b2a_hex(result).decode()

    def get_signature(self, seq: int, is_login: bool, hash: str, nn: str, ee: str) -> str:
        if is_login:
            s = '{}&h={}&s={}'.format(self._get_aes_string(), hash, seq)
        else:
            s = 'h={}&s={}'.format(hash, seq)

        sign = ''
        pos = 0

        while pos < len(s):
            sign = sign + self.rsa_encrypt(s[pos:pos + 53], nn, ee)
            pos = pos + 53

        return sign

    def _pad(self, s: str) -> str:
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def _unpad(s):
        if not s:
            return s
        return s[:-ord(s[len(s) - 1:])]

    def _get_aes_string(self) -> str:
        return 'k={}&i={}'.format(self._key.decode(), self._iv.decode())

    @staticmethod
    def encrypt_password_C1200(password: str, nn: str, ee: str) -> str:
        n = int(nn, 16)
        e = int(ee, 16)
        key = RSA.construct((n, e))

        modulus_byte_length = (key.size_in_bits() + 7) // 8
        password_bytes = password.encode('utf-8')
        if len(password_bytes) > modulus_byte_length:
            raise ValueError("Password too long for the RSA key size.")

        padded_password = password_bytes.ljust(modulus_byte_length, b'\x00')
        message_int = bytes_to_long(padded_password)
        encrypted_int = pow(message_int, e, n)
        encrypted_hex = format(encrypted_int, 'x').zfill(256)

        return encrypted_hex


class EncryptionWrapperMR:
    RSA_USE_PKCS_V1_5 = False
    AES_KEY_LEN = 128 // 8
    AES_IV_LEN = 16

    def __init__(self) -> None:
        ts = str(round(time() * 1000))

        key = (ts + str(randint(100000000, 1000000000 - 1)))[:self.AES_KEY_LEN]
        iv = (ts + str(randint(100000000, 1000000000 - 1)))[:self.AES_IV_LEN]

        assert len(key) == self.AES_KEY_LEN
        assert len(iv) == self.AES_IV_LEN

        self._key = key
        self._iv = iv

    def aes_encrypt(self, raw: str) -> str:
        # pad to a multiple of 16 with pkcs7
        data_padded = pad(raw.encode('utf8'), 16, 'pkcs7')

        # encrypt the body
        aes_encryptor = self._make_aes_cipher()
        encrypted_data_bytes = aes_encryptor.encrypt(data_padded)

        # encode encrypted binary data to base64
        return b64encode(encrypted_data_bytes).decode('utf8')

    def aes_decrypt(self, data: str):
        # decode base64 string
        encrypted_response_data = b64decode(data)

        # decrypt the response using our AES key
        aes_decryptor = self._make_aes_cipher()
        response = aes_decryptor.decrypt(encrypted_response_data)

        # unpad using pkcs7
        return unpad(response, 16, 'pkcs7').decode('utf8')

    def get_signature(self, seq: int, is_login: bool, hash: str, nn: str, ee: str) -> str:
        if is_login:
            # on login we also send our AES key, which is subsequently
            # used for E2E encrypted communication

            sign_data = 'key={}&iv={}&h={}&s={}'.format(self._key, self._iv, hash, seq)
        else:
            sign_data = 'h={}&s={}'.format(hash, seq)

        # set step based on whether PKCS padding is used
        rsa_byte_len = len(nn) // 2  # hexlen / 2 * 8 / 8
        step = (rsa_byte_len - 11) if self.RSA_USE_PKCS_V1_5 else rsa_byte_len

        # encrypt the signature using the RSA public key
        rsa_key = self._make_rsa_pub_key(nn, ee)

        # make the PKCS#1 v1.5 cipher
        if self.RSA_USE_PKCS_V1_5:
            rsa = PKCS1_v1_5.new(rsa_key)

        signature = ''
        pos = 0

        while pos < len(sign_data):
            sign_data_bin = sign_data[pos: pos + step].encode('utf8')

            if self.RSA_USE_PKCS_V1_5:
                # encrypt using the PKCS#1 v1.5 padding
                enc = rsa.encrypt(sign_data_bin)
            else:
                # encrypt using NOPADDING
                # ... pad the end with zero bytes
                while len(sign_data_bin) < step:
                    sign_data_bin = sign_data_bin + b'\0'

                # step 3a (OS2IP)
                em_int = bytes_to_long(sign_data_bin)

                # step 3b (RSAEP)
                m_int = rsa_key._encrypt(em_int)

                # step 3c (I2OSP)
                enc = long_to_bytes(m_int, 1)

            # hexlify to string
            enc_str = hexlify(enc).decode('utf8')

            # pad the start with '0' hex char
            while len(enc_str) < rsa_byte_len * 2:
                enc_str = '0' + enc_str

            signature += enc_str
            pos = pos + step

        return signature

    def _make_aes_cipher(self) -> AES:
        return AES.new(self._key.encode('utf8'), AES.MODE_CBC, iv=self._iv.encode('utf8'))

    @staticmethod
    def _make_rsa_pub_key(nn: str, ee: str):
        '''
        Makes a new RSA pub key from tuple (n, e)
        '''
        n = int('0x' + nn, 16)
        e = int('0x' + ee, 16)
        return RSA.construct((n, e))


class EncryptionWrapperMRGCM:
    RSA_USE_PKCS_V1_5 = False
    AES_KEY_LEN = 128 // 8
    AES_IV_LEN = 12  # previously 16

    def __init__(self) -> None:
        ts = str(round(time() * 1000))

        key = (ts + str(randint(100000000, 1000000000 - 1)))[:self.AES_KEY_LEN]
        iv = (ts + str(randint(100000000, 1000000000 - 1)))[:self.AES_IV_LEN]

        assert len(key) == self.AES_KEY_LEN
        assert len(iv) == self.AES_IV_LEN

        self._key = key
        self._iv = iv

    def aes_encrypt(self, raw: str) -> tuple[str, str]:
        # not sure what the padding was for here:
        # data_padded = pad(raw.encode('utf8'), 16, 'pkcs7')

        # encrypt the body
        aes_encryptor = self._make_aes_cipher()
        encrypted_data_bytes, tag = aes_encryptor.encrypt_and_digest(raw.encode('utf-8'))
        return (
            b64encode(encrypted_data_bytes).decode(),  # router expects b64 ciphertext
            b64encode(tag).decode()  # router expects b64 tag (this is new)
        )

    def aes_decrypt(self, data: str):
        # decode base64 string
        tag = b64decode(data[-24:])  # last 24 characters are the tag
        encrypted_response_data = b64decode(data[:-24])
        # decrypt the response using our AES key
        aes_decryptor = self._make_aes_cipher()
        response = aes_decryptor.decrypt_and_verify(encrypted_response_data, tag)

        # not sure what unpad did here before:
        # return unpad(response, 16, 'pkcs7').decode('utf8')
        return response.decode('utf8')

    def get_signature(self, seq: int, is_login: bool, hash: str, nn: str, ee: str) -> str:
        if is_login:
            # on login we also send our AES key, which is subsequently
            # used for E2E encrypted communication
            # key and iv now base64 not like before
            key = b64encode(self._key.encode('utf-8')).decode()
            iv = b64encode(self._iv.encode('utf-8')).decode()
            sign_data = 'key={}&iv={}&h={}&s={}'.format(key, iv, hash, seq)
        else:
            sign_data = 'h={}&s={}'.format(hash, seq)

        # set step based on whether PKCS padding is used
        rsa_byte_len = len(nn) // 2  # hexlen / 2 * 8 / 8
        step = (rsa_byte_len - 11) if self.RSA_USE_PKCS_V1_5 else rsa_byte_len

        # encrypt the signature using the RSA public key
        rsa_key = self._make_rsa_pub_key(nn, ee)

        # make the PKCS#1 v1.5 cipher
        if self.RSA_USE_PKCS_V1_5:
            rsa = PKCS1_v1_5.new(rsa_key)

        signature = ''
        pos = 0

        while pos < len(sign_data):
            sign_data_bin = sign_data[pos: pos + step].encode('utf8')

            if self.RSA_USE_PKCS_V1_5:
                # encrypt using the PKCS#1 v1.5 padding
                enc = rsa.encrypt(sign_data_bin)
            else:
                # encrypt using NOPADDING
                # ... pad the end with zero bytes
                while len(sign_data_bin) < step:
                    sign_data_bin = sign_data_bin + b'\0'

                # step 3a (OS2IP)
                em_int = bytes_to_long(sign_data_bin)

                # step 3b (RSAEP)
                m_int = rsa_key._encrypt(em_int)

                # step 3c (I2OSP)
                enc = long_to_bytes(m_int, 1)

            # hexlify to string
            enc_str = hexlify(enc).decode('utf8')

            # pad the start with '0' hex char
            while len(enc_str) < rsa_byte_len * 2:
                enc_str = '0' + enc_str

            signature += enc_str
            pos = pos + step

        return signature

    def _make_aes_cipher(self) -> AES:
        # consider renaming _iv to _nonce
        return AES.new(self._key.encode('utf-8'), AES.MODE_GCM, nonce=self._iv.encode('utf-8'))

    @staticmethod
    def _make_rsa_pub_key(nn: str, ee: str):
        '''
        Makes a new RSA pub key from tuple (n, e)
        '''
        n = int('0x' + nn, 16)
        e = int('0x' + ee, 16)
        return RSA.construct((n, e))


class EncryptionWrapperMRECC:
    """
    Used by MR-series routers whose firmware replaced the legacy RSA key exchange
    with ECIES over NIST P-224 (this mirrors TP-Link's own client-side crypto,
    served by the router itself as ecc.min.js/tpEncrypt.js - stock SJCL under the
    hood). Session payload cipher is still AES-128-CBC/PKCS7, same as
    EncryptionWrapperMR, but the per-request signature is ECIES-encrypted instead
    of RSA-encrypted, and each request additionally carries a separate
    HMAC-SHA256 (keyed with the raw ASCII session AES key) over the plaintext
    payload, appended as a 4th field alongside the ECIES iv/ct/tag.
    """
    AES_KEY_LEN = 128 // 8
    AES_IV_LEN = 16
    ECC_FIELD_BYTES = 28  # NIST P-224 = 224 bits

    def __init__(self) -> None:
        ts = str(round(time() * 1000))

        key = (ts + str(randint(100000000, 1000000000 - 1)))[:self.AES_KEY_LEN]
        iv = (ts + str(randint(100000000, 1000000000 - 1)))[:self.AES_IV_LEN]

        assert len(key) == self.AES_KEY_LEN
        assert len(iv) == self.AES_IV_LEN

        self._key = key
        self._iv = iv

    def aes_encrypt(self, raw: str) -> str:
        data_padded = pad(raw.encode('utf8'), 16, 'pkcs7')
        aes_encryptor = self._make_aes_cipher()
        encrypted_data_bytes = aes_encryptor.encrypt(data_padded)
        return b64encode(encrypted_data_bytes).decode('utf8')

    def aes_decrypt(self, data: str):
        encrypted_response_data = b64decode(data)
        aes_decryptor = self._make_aes_cipher()
        response = aes_decryptor.decrypt(encrypted_response_data)
        return unpad(response, 16, 'pkcs7').decode('utf8')

    def compute_hmac(self, data: str) -> str:
        h = CryptoHMAC.new(self._key.encode('utf-8'), digestmod=CryptoSHA256)
        h.update(data.encode('utf-8'))
        return h.hexdigest()

    def get_signature(self, seq: int, is_login: bool, hash: str, ecc_pub_hex: str, hmac_hex: str) -> str:
        if is_login:
            # on login we also send our AES key, which is subsequently
            # used for E2E encrypted communication
            sign_data = 'key={}&iv={}&h={}&s={}'.format(self._key, self._iv, hash, seq)
        else:
            sign_data = 'h={}&s={}'.format(hash, seq)

        sign_obj = self._ecies_encrypt(sign_data, ecc_pub_hex)
        sign_obj['hmac'] = hmac_hex

        return json_dumps(sign_obj)

    def _ecies_encrypt(self, plaintext: str, ecc_pub_hex: str) -> dict:
        # ecc_pub_hex = '224' + X_HEX(56 chars) + Y_HEX(56 chars), as served by
        # the router's own /cgi/getParm response
        assert ecc_pub_hex[:3] == '224'
        x = int(ecc_pub_hex[3:3 + 56], 16)
        y = int(ecc_pub_hex[3 + 56:3 + 112], 16)
        router_pub = EccPoint(x, y, curve='p224')

        curve = _ecc_curves['p224']
        order = int(curve.order)
        e = int.from_bytes(Random.get_random_bytes(32), 'big') % (order - 1) + 1

        ephemeral_pub = curve.G * e
        tag_hex = (
            int(ephemeral_pub.x).to_bytes(self.ECC_FIELD_BYTES, 'big')
            + int(ephemeral_pub.y).to_bytes(self.ECC_FIELD_BYTES, 'big')
        ).hex()

        shared_point = router_pub * e
        shared_x_bytes = int(shared_point.x).to_bytes(self.ECC_FIELD_BYTES, 'big')
        kem_key = CryptoSHA256.new(shared_x_bytes).digest()[:16]

        ecies_iv = Random.get_random_bytes(16)
        cipher = AES.new(kem_key, AES.MODE_CBC, iv=ecies_iv)
        ct = cipher.encrypt(pad(plaintext.encode('utf-8'), 16))

        return {'iv': ecies_iv.hex(), 'ct': ct.hex(), 'tag': tag_hex}

    def _make_aes_cipher(self) -> AES:
        return AES.new(self._key.encode('utf8'), AES.MODE_CBC, iv=self._iv.encode('utf8'))
