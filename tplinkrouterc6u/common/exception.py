# Modified 2026-11-24: add sanitized errors for verified Deco Wi-Fi writes.
from collections.abc import Mapping
from types import MappingProxyType

from tplinkrouterc6u.common.package_enum import Connection


class ClientException(Exception):
    pass


class ClientError(ClientException):
    pass


class AuthorizeError(ClientException):
    pass


class WifiVerificationError(ClientException):
    """A safe failure carrying only recognized WLAN states, never raw data."""

    message = 'Wi-Fi verification failed'

    def __init__(self, latest_states: Mapping[Connection, bool] | None = None,
                 error_type: str | None = None) -> None:
        super().__init__(self.message)
        self.latest_states = MappingProxyType({
            wifi: value for wifi, value in (latest_states or {}).items()
            if isinstance(wifi, Connection) and type(value) is bool
        })
        self.error_type = error_type


class WifiWriteNotObserved(WifiVerificationError):
    message = 'Requested Wi-Fi state was not observed'


class WifiVerificationUnavailable(WifiVerificationError):
    message = 'Wi-Fi state could not be verified'


class WifiWriteRejected(WifiVerificationError):
    message = 'Router rejected the Wi-Fi write'
