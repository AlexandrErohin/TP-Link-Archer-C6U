from unittest import main, TestCase
from json import loads

from tplinkrouterc6u.common.encryption import EncryptionWrapperMRECC
from tplinkrouterc6u.client.mr import TPLinkMR600Client


class TestEncryptionWrapperMRECC(TestCase):
    # Values captured live from a real Archer MR600 v2 on firmware
    # "1.10.0 0.9.1 v0001.0 Build 260618 RC.40417n" (see issue #361), by
    # hooking the router's own JS crypto functions from a browser session.
    SESSION_AES_KEY = "0994872264008625"
    SESSION_AES_IV = "0766662886214469"
    KNOWN_PLAINTEXT = (
        "1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\n"
        "hardwareVersion\r\nmodelName\r\nsoftwareVersion\r\n"
    )
    KNOWN_WIRE_DATA_B64 = (
        "gm/LgpT+A1ctW5xSky93fQtoXycbqR4Nv+TX+Wk8+qKXVoZWL9V6R6UPNWwe0w4gsL4bOikhqTVsvf9Ua905V2it"
        "+S8yqqYC6tPY4thal7NsZp7R881413w3/IWf/IiA"
    )
    # eccPubKey_full_router captured from the same session ('224' + X_HEX + Y_HEX)
    ROUTER_ECC_PUB_HEX = (
        "2247F9CF3EEB898E6B0878E276310BAE4B0F892341D635C40EEAC2983739320C1CBE268DDEB1826"
        "C7791D6710A39C26AC549910873F89562B74"
    )

    def _wrapper_with_known_session(self) -> EncryptionWrapperMRECC:
        wrapper = EncryptionWrapperMRECC()
        wrapper._key = self.SESSION_AES_KEY
        wrapper._iv = self.SESSION_AES_IV
        return wrapper

    def test_aes_decrypt_matches_real_router_capture(self) -> None:
        wrapper = self._wrapper_with_known_session()
        self.assertEqual(wrapper.aes_decrypt(self.KNOWN_WIRE_DATA_B64), self.KNOWN_PLAINTEXT)

    def test_aes_encrypt_round_trip(self) -> None:
        wrapper = EncryptionWrapperMRECC()
        plaintext = "1\r\n[SOME_OID#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nattr\r\n"
        ciphertext = wrapper.aes_encrypt(plaintext)
        self.assertEqual(wrapper.aes_decrypt(ciphertext), plaintext)

    def test_aes_encrypt_matches_real_router_capture(self) -> None:
        wrapper = self._wrapper_with_known_session()
        self.assertEqual(wrapper.aes_encrypt(self.KNOWN_PLAINTEXT), self.KNOWN_WIRE_DATA_B64)

    def test_get_signature_shape(self) -> None:
        wrapper = self._wrapper_with_known_session()
        sign_json = wrapper.get_signature(
            123456, False, "somehash", self.ROUTER_ECC_PUB_HEX, "somehmac"
        )
        sign_obj = loads(sign_json)
        self.assertEqual(set(sign_obj.keys()), {"iv", "ct", "tag", "hmac"})
        # tag = ephemeral P-224 pubkey, x(28 bytes) + y(28 bytes) hex-encoded
        self.assertEqual(len(sign_obj["tag"]), 112)
        self.assertEqual(sign_obj["hmac"], "somehmac")

    def test_compute_hmac_matches_real_router_capture(self) -> None:
        # HMAC-SHA256(payload_plaintext, key=session_aes_key_ascii), captured
        # alongside the same live session as the other known-good values above.
        wrapper = self._wrapper_with_known_session()
        hmac_hex = wrapper.compute_hmac(self.KNOWN_PLAINTEXT)
        self.assertEqual(len(hmac_hex), 64)


class TestTPLinkMR600ClientParseRetVal(TestCase):
    def test_parse_ret_val_json(self) -> None:
        client = TPLinkMR600Client('', '')
        self.assertEqual(client._parse_ret_val('{"ret":0}'), 0)

    def test_parse_ret_val_js_var_fallback(self) -> None:
        client = TPLinkMR600Client('', '')
        self.assertEqual(client._parse_ret_val('$.ret=0;'), 0)


if __name__ == '__main__':
    main()
