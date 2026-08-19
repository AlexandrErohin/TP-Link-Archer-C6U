from unittest import main, TestCase

from tplinkrouterc6u.common.encryption import EncryptionWrapper


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


if __name__ == '__main__':
    main()
