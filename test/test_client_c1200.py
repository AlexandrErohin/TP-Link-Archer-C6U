import unittest
import json
from tplinkrouterc6u import (
    TplinkC1200Router,
    ClientException
)


class TestTPLinkC1200Client(unittest.TestCase):

    def test_set_led_on(self) -> None:

        response_led_general_read = '''
        {
            "enable": "off",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        '''

        response_led_general_write = '''
        {
            "enable": "on",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        '''

        class TPLinkRouterTest(TplinkC1200Router):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/ledgeneral?form=setting&operation=read':
                    return json.loads(response_led_general_read)
                if path == 'admin/ledgeneral?form=setting&operation=write':
                    self.captured_path = path
                    return json.loads(response_led_general_write)
                raise ClientException()

        client = TPLinkRouterTest('', '')
        
        client.set_led(True)

        expected_path = "admin/ledgeneral?form=setting&operation=write"
        
        self.assertEqual(client.captured_path, expected_path)

    def test_set_led_off(self) -> None:

        response_led_general_read = '''
        {
            "enable": "on",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        '''

        response_led_general_write = '''
        {
            "enable": "off",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        '''

        class TPLinkRouterTest(TplinkC1200Router):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/ledgeneral?form=setting&operation=read':
                    return json.loads(response_led_general_read)
                elif path == 'admin/ledgeneral?form=setting&operation=write':
                    self.captured_path = path
                    return json.loads(response_led_general_write)
                raise ClientException()

        client = TPLinkRouterTest('', '')

        client.set_led(False)

        expected_path = "admin/ledgeneral?form=setting&operation=write"
        
        self.assertEqual(client.captured_path, expected_path)

    def test_led_status(self) -> None:

        response_led_general_read = '''
        {
            "enable": "on",
            "time_set": "yes",
            "ledpm_support": "yes"
        }
        '''
        
        class TPLinkRouterTest(TplinkC1200Router):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
                if path == 'admin/ledgeneral?form=setting&operation=read':
                    return json.loads(response_led_general_read)
                raise ClientException()

        client = TPLinkRouterTest('', '')

        led_status = client.get_led()
        self.assertTrue(led_status)

if __name__ == '__main__':
    unittest.main()
