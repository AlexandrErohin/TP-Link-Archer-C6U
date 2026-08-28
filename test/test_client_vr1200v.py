from unittest import TestCase, main
from unittest.mock import Mock

from tplinkrouterc6u.client.vr1200v import TplinkVR1200vRouter
from tplinkrouterc6u.common.dataclass import Firmware
from tplinkrouterc6u.common.exception import ClientException


class TestTplinkVR1200vBackup(TestCase):

    def _client(self, firmware: Firmware):
        class TplinkVR1200vRouterTest(TplinkVR1200vRouter):
            def get_firmware(self) -> Firmware:
                return firmware

        client = TplinkVR1200vRouterTest('http://192.168.1.1', 'password')
        client._token = 'test_token'
        return client

    def test_backup_config_builds_path_and_returns_content(self) -> None:
        firmware = Firmware('Archer VR1200v V1', 'VR1200v', '1.0.0 Build 200714 Rel.2239n')
        client = self._client(firmware)

        response = Mock()
        response.status_code = 200
        response.content = b'backup-binary-data'
        client.req.get = Mock(return_value=response)

        result = client.backup_config()

        client.req.get.assert_called_once()
        url = client.req.get.call_args[0][0]
        self.assertTrue(url.startswith('http://192.168.1.1/cgi/ArcherVR1200vV12007142239n.bin?'))
        headers = client.req.get.call_args[1]['headers']
        self.assertEqual(headers.get('TokenID'), 'test_token')
        self.assertEqual(result, b'backup-binary-data')

    def test_backup_config_raises_on_unmatched_firmware(self) -> None:
        client = self._client(Firmware('Unknown Model', 'Unknown', 'Unknown'))

        with self.assertRaises(ClientException):
            client.backup_config()

    def test_backup_config_raises_when_not_authorized(self) -> None:
        firmware = Firmware('Archer VR1200v V1', 'VR1200v', '1.0.0 Build 200714 Rel.2239n')

        class TplinkVR1200vRouterTest(TplinkVR1200vRouter):
            def get_firmware(self) -> Firmware:
                return firmware

        client = TplinkVR1200vRouterTest('http://192.168.1.1', 'password')

        with self.assertRaises(ClientException):
            client.backup_config()

    def test_backup_config_raises_on_http_error(self) -> None:
        client = self._client(Firmware('Archer VR1200v V1', 'VR1200v', '1.0.0 Build 200714 Rel.2239n'))

        response = Mock()
        response.status_code = 500
        client.req.get = Mock(return_value=response)

        with self.assertRaises(ClientException):
            client.backup_config()


if __name__ == '__main__':
    main()
