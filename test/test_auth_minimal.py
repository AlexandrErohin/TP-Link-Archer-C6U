from unittest import main, TestCase
from unittest.mock import patch
from tplinkrouterc6u import TplinkRouter


class TestAuthMinimal(TestCase):
    def setUp(self):
        self.client = TplinkRouter('http://192.168.0.1', 'test_password')
        self.client._seq = '100'
        self.client.nn = '00'
        self.client.ee = '010001'

    def test_prepare_data_signature_state(self):
        # Verify conditional signature logic (True for login, False for active session)
        with patch.object(self.client._encryption, 'aes_encrypt', return_value='enc'), \
             patch.object(self.client._encryption, 'get_signature', return_value='sign') as mock_sign:
            
            self.client._logged = False
            self.client._prepare_data('data')
            self.assertTrue(mock_sign.call_args[0][1], "Should pass True when not logged")
            
            self.client._logged = True
            self.client._prepare_data('data')
            self.assertFalse(mock_sign.call_args[0][1], "Should pass False when logged")


if __name__ == '__main__':
    main()
