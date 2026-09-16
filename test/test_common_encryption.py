from unittest import main, TestCase

from Crypto.PublicKey import RSA

from tplinkrouterc6u.common.encryption import (
    EncryptionWrapper,
    EncryptionWrapperMRGCM,
    EncryptionWrapperMRGCMOAEP,
)


class TestEncryptionWrapper(TestCase):
    def test_unpad_empty_string_returns_empty(self) -> None:
        """Empty input must not raise (older code called ord('') and crashed)."""
        self.assertEqual(EncryptionWrapper._unpad(''), '')

    def test_unpad_empty_bytes_returns_empty(self) -> None:
        self.assertEqual(EncryptionWrapper._unpad(b''), b'')

    def test_unpad_round_trip(self) -> None:
        wrapper = EncryptionWrapper()
        plaintext = 'hello world'
        ciphertext = wrapper.aes_encrypt(plaintext)
        self.assertEqual(wrapper.aes_decrypt(ciphertext), plaintext)

    def test_aes_decrypt_ignores_invalid_utf8_bytes(self) -> None:
        """Garbage bytes in a decrypted payload (e.g. a device nickname with
        invalid UTF-8 from the Deco app, HA #374) must not crash decrypt —
        the surrounding JSON must still parse."""
        from base64 import b64encode
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        wrapper = EncryptionWrapper()
        # Build a valid JSON string that also contains an invalid UTF-8 byte
        # sequence (0xab is not a valid start byte in UTF-8).
        raw = b'{"nickname":"abc\xab\x99xyz"}'
        cipher = AES.new(wrapper._key, AES.MODE_CBC, wrapper._iv)
        ciphertext = b64encode(cipher.encrypt(pad(raw, AES.block_size))).decode()

        result = wrapper.aes_decrypt(ciphertext)
        # Invalid bytes are dropped, but the surrounding valid text survives.
        self.assertIn('nickname', result)
        self.assertIn('abc', result)
        self.assertIn('xyz', result)


class TestEncryptionWrapperMRGCMOAEP(TestCase):
    """RSA-OAEP signatures for EX920-class firmwares (HA #393)."""

    # Same public 512-bit auth key used in test_client_ax72 / test_client_sg.
    NN = (
        'ca8f1711cc27576fb0dae0d7df1b6a90465e8ea31ccf46b0004f4c60f6617df'
        '8fa147502e45353b4d3f8ad38cb9aee9a77d33973ce3d7d681bc2fb0ae242e631'
    )
    EE = '010001'

    def test_oaep_login_signature_is_five_512bit_blocks(self) -> None:
        """Browser captures on EX920 show sign=640 hex (5 OAEP blocks);
        no-padding GCM produces 256 hex (2 blocks) and the router closes
        the connection (RemoteDisconnected).
        """
        wrapper = EncryptionWrapperMRGCMOAEP()
        wrapper._key = '1234567890123456'
        wrapper._iv = '123456789012'  # GCM nonce length

        sign = wrapper.get_signature(
            seq=555111222,
            is_login=True,
            hash='a' * 32,  # MD5 hex
            nn=self.NN,
            ee=self.EE,
        )

        self.assertEqual(len(sign), 640)
        self.assertEqual(len(sign) % len(self.NN), 0)

    def test_legacy_gcm_no_padding_signature_stays_two_blocks(self) -> None:
        """Regression: default MRGCM must keep no-padding 2-block signatures."""
        wrapper = EncryptionWrapperMRGCM()
        wrapper._key = '1234567890123456'
        wrapper._iv = '123456789012'

        sign = wrapper.get_signature(
            seq=555111222,
            is_login=True,
            hash='a' * 32,
            nn=self.NN,
            ee=self.EE,
        )

        self.assertEqual(len(sign), 256)

    def test_oaep_chunks_are_decryptable(self) -> None:
        """Each RSA block must be a valid OAEP ciphertext under the key."""
        from Crypto.Cipher import PKCS1_OAEP

        # pycryptodome rejects RSA.generate(512); 1024-bit is enough to
        # prove PKCS1_OAEP round-trip of our chunking.
        key = RSA.generate(1024)
        rsa_byte_len = (key.size_in_bits() + 7) // 8
        nn = format(key.n, 'x').zfill(rsa_byte_len * 2)
        ee = format(key.e, 'x')

        wrapper = EncryptionWrapperMRGCMOAEP()
        wrapper._key = '1234567890123456'
        wrapper._iv = '123456789012'
        sign = wrapper.get_signature(100, True, 'b' * 32, nn, ee)

        rsa = PKCS1_OAEP.new(key)
        block_hex = len(nn)
        self.assertGreater(len(sign), 0)
        self.assertEqual(len(sign) % block_hex, 0)
        for i in range(0, len(sign), block_hex):
            block = bytes.fromhex(sign[i:i + block_hex])
            # Must not raise ValueError (bad padding / decrypt failure)
            rsa.decrypt(block)


if __name__ == '__main__':
    main()
