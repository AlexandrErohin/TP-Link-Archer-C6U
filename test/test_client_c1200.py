from unittest import main, TestCase
from json import loads
from tplinkrouterc6u import (
    TplinkC1200Router,
    Connection,
    ClientException
)


class TestTPLinkC1200Client(TestCase):

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
                    return loads(response_led_general_read)
                if path == 'admin/ledgeneral?form=setting&operation=write':
                    self.captured_path = path
                    return loads(response_led_general_write)
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
                    return loads(response_led_general_read)
                elif path == 'admin/ledgeneral?form=setting&operation=write':
                    self.captured_path = path
                    return loads(response_led_general_write)
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
                    return loads(response_led_general_read)
                raise ClientException()

        client = TPLinkRouterTest('', '')

        led_status = client.get_led()
        self.assertTrue(led_status)

    def test_set_wifi(self) -> None:

        class TPLinkRouterTest(TplinkC1200Router):
            def request(self, path: str, data: str,
                        ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:

                self.captured_path = path
                self.captured_data = data

        client = TPLinkRouterTest('', '')
        client.set_wifi(
            Connection.HOST_5G,
            enable=True,
            ssid="TestSSID",
            hidden="no",
            encryption="WPA3-PSK",
            psk_version="2",
            psk_cipher="AES",
            psk_key="testkey123",
            hwmode="11ac",
            htmode="VHT20",
            channel=36,
            txpower="20",
            disabled_all="no"
        )

        expected_data = ("operation=write&enable=on&ssid=TestSSID&hidden=no&encryption=WPA3-PSK&"
                         "psk_version=2&psk_cipher=AES&psk_key=testkey123&hwmode=11ac&"
                         "htmode=VHT20&channel=36&txpower=20&disabled_all=no")
        expected_path = f"admin/wireless?form=wireless_5g&{expected_data}"

        self.assertEqual(client.captured_path, expected_path)
        self.assertEqual(client.captured_data, expected_data)


if __name__ == '__main__':
    main()
