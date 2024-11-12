from ipaddress import IPv4Address
from macaddress import EUI48


def get_ip(ip: str) -> IPv4Address:
    try:
        return IPv4Address(ip)
    except Exception:
        return IPv4Address('0.0.0.0')


def get_mac(mac: str) -> EUI48:
    try:
        return EUI48(mac)
    except Exception:
        return EUI48('00:00:00:00:00:00')
