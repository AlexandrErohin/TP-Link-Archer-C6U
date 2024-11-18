from enum import Enum


class Connection(Enum):
    HOST_2G = 'host_2g'
    HOST_5G = 'host_5g'
    HOST_6G = 'host_6g'
    GUEST_2G = 'guest_2g'
    GUEST_5G = 'guest_5g'
    GUEST_6G = 'guest_6g'
    IOT_2G = 'iot_2g'
    IOT_5G = 'iot_5g'
    IOT_6G = 'iot_6g'
    WIRED = 'wired'
    UNKNOWN = 'unknown'

    def is_host_wifi(self) -> bool:
        return self in [Connection.HOST_2G, Connection.HOST_5G, Connection.HOST_6G]

    def is_guest_wifi(self) -> bool:
        return self in [Connection.GUEST_2G, Connection.GUEST_5G, Connection.GUEST_5G]

    def is_iot(self) -> bool:
        return self in [Connection.IOT_2G, Connection.IOT_5G, Connection.IOT_6G]

    def get_band(self) -> str | None:
        band = None
        if self in [Connection.HOST_2G, Connection.GUEST_2G, Connection.IOT_2G]:
            band = '2G'
        elif self in [Connection.HOST_5G, Connection.GUEST_5G, Connection.IOT_5G]:
            band = '5G'
        elif self in [Connection.HOST_6G, Connection.GUEST_6G, Connection.IOT_6G]:
            band = '6G'
        return band

    def get_type(self) -> str | None:
        band = None
        if self.is_host_wifi():
            band = 'host'
        elif self.is_guest_wifi():
            band = 'guest'
        elif self.is_iot():
            band = 'IoT'
        elif self == Connection.WIRED:
            band = 'wired'
        return band


class VPN(Enum):
    OPEN_VPN = 'OPENVPN'
    PPTP_VPN = 'PPTPVPN'
