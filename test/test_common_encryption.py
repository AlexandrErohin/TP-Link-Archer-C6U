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


if __name__ == '__main__':
    main()
