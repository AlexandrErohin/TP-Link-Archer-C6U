"""Shared configuration-backup support.

The router settings backup is downloaded from an endpoint whose path is
derived from the firmware version strings. The exact path format is shared
across device families, but the authenticated HTTP call differs per client
(auth headers, token, session, stok, ...). This mixin centralises the path
parsing and delegates the actual download to a small per-client hook
(`_backup_get`), so new models that use the same `/cgi/*.bin?` backup API
can be supported by subclassing the mixin and implementing `_backup_get`.
"""

import re

from tplinkrouterc6u.common.dataclass import Firmware
from tplinkrouterc6u.common.exception import ClientException

# Matches e.g. "Archer VR1200v V1" -> ("Archer VR1200v", "V1")
_HW_RE = re.compile(r'^([A-Za-z0-9 .]+) ([vV][0-9]+)')
# Matches e.g. "1.0.0 Build 200714 Rel.2239n" -> ("200714", "2239n")
_FW_RE = re.compile(r'.* Build ([0-9]+) Rel\.([0-9a-zA-Z]+)')


class ConfigBackupMixin:
    """Adds backup_config() to a client using the /cgi/<model><ver>.bin API."""

    def backup_config(self) -> bytes:
        """Download and return the router configuration backup as bytes."""
        firmware = self.get_firmware()
        path = self._build_backup_path(firmware)
        return self._backup_get(path)

    def _build_backup_path(self, firmware: Firmware) -> str:
        hw = _HW_RE.match(firmware.hardware_version)
        fw = _FW_RE.match(firmware.firmware_version)
        if not hw or not fw:
            raise ClientException(
                'Unable to build backup path from firmware info: {} / {}'.format(
                    firmware.hardware_version, firmware.firmware_version))

        hw_prefix = hw.group(1).replace(' ', '')
        hw_version = hw.group(2).upper()
        fw_build = fw.group(1)
        fw_release = fw.group(2).lower()

        return '/cgi/{}{}{}{}.bin?'.format(hw_prefix, hw_version, fw_build, fw_release)

    def _backup_get(self, path: str) -> bytes:
        """Perform the authenticated GET for the backup file.

        Subclasses must implement this using their own auth mechanism
        (token headers, stok, session, ...) and return the raw bytes.
        """
        raise NotImplementedError
