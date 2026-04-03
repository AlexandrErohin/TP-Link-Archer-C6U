from unittest import main, TestCase
from unittest.mock import Mock

from tplinkrouterc6u import TPLinkEAP115Client


class TestTPLinkEAP115Client(TestCase):
    def test_supports_success(self) -> None:
        client = TPLinkEAP115Client('http://192.168.0.10', 'password')
        client._session = Mock()
        client._session.cookies = Mock()
        client._session.cookies.clear = Mock()

        seed = Mock()
        seed.status_code = 200

        login = Mock()
        login.status_code = 200

        ap_list = Mock()
        ap_list.status_code = 200
        ap_list.json.return_value = {
            'success': True,
            'data': [{'MAC': 'AA:BB:CC:DD:EE:FF'}],
        }

        client._session.get.side_effect = [seed, ap_list]
        client._session.post.return_value = login

        self.assertTrue(client.supports())

    def test_get_status_maps_devices(self) -> None:
        client = TPLinkEAP115Client('http://192.168.0.10', 'password')
        client._session = Mock()

        ap_list = Mock()
        ap_list.status_code = 200
        ap_list.json.return_value = {
            'success': True,
            'data': [{'MAC': 'AA:BB:CC:DD:EE:FF'}],
        }

        client_list = Mock()
        client_list.status_code = 200
        client_list.json.return_value = {
            'success': True,
            'data': [
                {
                    'MAC': 'AA-BB-CC-DD-EE-FF',
                    'IP': '192.168.1.2',
                    'name': 'host1',
                }
            ],
        }
        client._session.get.side_effect = [ap_list, client_list]

        status = client.get_status()
        self.assertEqual(status.clients_total, 1)
        self.assertEqual(len(status.devices), 1)
        self.assertEqual(status.devices[0].macaddr.lower(), 'aa-bb-cc-dd-ee-ff')

    def test_get_firmware_falls_back_to_ap_list(self) -> None:
        client = TPLinkEAP115Client('http://192.168.0.10', 'password')
        client._session = Mock()

        ap_list = Mock()
        ap_list.status_code = 200
        ap_list.json.return_value = {
            'success': True,
            'data': [
                {
                    'HardVer': '1.0/2.0',
                    'MAC': '02:00:00:00:00:01',
                    'Name': 'EAP115-02-00-00-00-00-01',
                    'StaNum': 0,
                }
            ],
        }

        dev_info = Mock()
        dev_info.status_code = 200
        dev_info.json.return_value = {
            'success': False,
            'data': None,
        }

        client._session.get.side_effect = [ap_list, dev_info]

        fw = client.get_firmware()
        self.assertEqual(fw.hardware_version, '1.0/2.0')
        self.assertEqual(fw.model, 'TP-Link EAP115')


if __name__ == '__main__':
    main()
