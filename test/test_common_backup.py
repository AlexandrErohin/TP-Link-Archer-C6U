from unittest import TestCase, main

from tplinkrouterc6u.common.backup import ConfigBackupMixin
from tplinkrouterc6u.common.dataclass import Firmware
from tplinkrouterc6u.common.exception import ClientException


class _Stub(ConfigBackupMixin):
    def __init__(self, firmware: Firmware):
        self._firmware = firmware
        self.got_path = None

    def get_firmware(self) -> Firmware:
        return self._firmware

    def _backup_get(self, path: str) -> bytes:
        self.got_path = path
        return b'backup-bytes'


class TestConfigBackupMixin(TestCase):

    def test_build_path(self) -> None:
        stub = _Stub(Firmware('Archer VR1200v V1', 'VR1200v', '1.0.0 Build 200714 Rel.2239n'))
        self.assertEqual(
            stub._build_backup_path(stub._firmware),
            '/cgi/ArcherVR1200vV12007142239n.bin?')

    def test_build_path_lowercase_version(self) -> None:
        stub = _Stub(Firmware('Archer VR1200v v1', 'VR1200v', '1.0.0 Build 200714 Rel.2239n'))
        self.assertEqual(
            stub._build_backup_path(stub._firmware),
            '/cgi/ArcherVR1200vV12007142239n.bin?')

    def test_build_path_raises_on_unmatched_firmware(self) -> None:
        stub = _Stub(Firmware('Unknown Model', 'Unknown', 'Unknown'))
        with self.assertRaises(ClientException):
            stub._build_backup_path(stub._firmware)

    def test_backup_config_delegates_to_backup_get(self) -> None:
        stub = _Stub(Firmware('Archer VR1200v V1', 'VR1200v', '1.0.0 Build 200714 Rel.2239n'))
        result = stub.backup_config()
        self.assertEqual(result, b'backup-bytes')
        self.assertEqual(stub.got_path, '/cgi/ArcherVR1200vV12007142239n.bin?')


if __name__ == '__main__':
    main()
