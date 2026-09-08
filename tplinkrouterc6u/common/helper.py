from ipaddress import IPv4Address, IPv6Address, AddressValueError
from macaddress import EUI48
import re
from base64 import b64decode


def is_valid_base64(s: str) -> bool:
    """Return True if s is a syntactically valid base64 string."""
    if len(s) % 4 != 0:
        return False
    if re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', s) is None:
        return False
    try:
        b64decode(s, validate=True)
        return True
    except Exception:
        return False


def get_ip(ip: str) -> IPv4Address:
    try:
        return IPv4Address(ip)
    except (AddressValueError, ValueError, TypeError):
        return IPv4Address('0.0.0.0')


def get_ipv6(ip: str) -> IPv6Address:
    try:
        return IPv6Address(ip)
    except (AddressValueError, ValueError, TypeError):
        return IPv6Address('::')


def get_mac(mac: str) -> EUI48:
    try:
        return EUI48(mac)
    except (ValueError, TypeError):
        return EUI48('00:00:00:00:00:00')


def get_value(dictionary, keys: list, default=None):
    nested_dict = dictionary

    for key in keys:
        try:
            nested_dict = nested_dict[key]
        except (KeyError, TypeError, IndexError):
            return default
    return nested_dict


def escape_act_attr_value(value: str) -> str:
    return value.replace('\r', '\x11').replace('\n', '\x12')


def unescape_act_attr_value(value: str) -> str:
    return value.replace('\x11', '\r').replace('\x12', '\n')
