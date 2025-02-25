from unittest import main
from test.test_client_mr import TestTPLinkMRClient
from tplinkrouterc6u.client.vr1200 import TPLinkVR1200Client


class TestClientVR1200(TestTPLinkMRClient):
    
    def test_check_modem(self):
        client = TPLinkVR1200Client('http://192.168.1.1', '', '')
        self.assertTrue(client._verify_modem())

if __name__ == "__main__":
    main()