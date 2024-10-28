from ipaddress import IPv4Address


def get_ip(ip: str) -> IPv4Address:
    try:
        return IPv4Address(ip)
    except Exception:
        return IPv4Address('0.0.0.0')
