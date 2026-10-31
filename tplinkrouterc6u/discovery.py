"""Opt-in, login-free fingerprinting for supported LuCI router families.

Discovery never submits credentials, modifies router state or calls supports().
Unsupported/ambiguous firmware is deliberately left unresolved; callers can
choose a client explicitly rather than risking multiple failed logins.
"""

from dataclasses import dataclass
from typing import Optional

from requests import post
from requests.exceptions import RequestException

from tplinkrouterc6u.client.sg import SG_CERTIFICATIONS


class DetectionError(Exception):
    """Passive detection could not identify a single supported API family."""


@dataclass(frozen=True)
class DetectionResult:
    client_name: Optional[str]
    confidence: str
    evidence: str


def discover_router(host: str, verify_ssl: bool = True,
                    timeout: int = 30) -> DetectionResult:
    """Identify a known LuCI API family without a login attempt.

    This deliberately covers only SG, V1_11 and classic LuCI. A UI skin or
    an unsuccessful probe is not enough to guess another model's auth mode.
    """
    if not host.startswith(('http://', 'https://')):
        host = 'http://' + host
    host = host.rstrip('/')
    # Keep passive checks bounded even if the main client timeout is large.
    probe_timeout = min(timeout, 5) if isinstance(timeout, (int, float)) else timeout
    config_url = host + '/cgi-bin/luci/;stok=/device_config?form=config'
    keys_url = host + '/cgi-bin/luci/;stok=/login?form=keys'

    try:
        response = post(config_url, data='operation=read',
                        timeout=probe_timeout, verify=verify_ssl)
        data = response.json().get('data', {})
        certs = data.get('certification', []) if isinstance(data, dict) else []
        if isinstance(certs, list) and any(c in SG_CERTIFICATIONS for c in certs):
            return DetectionResult('TplinkRouterSG', 'high', 'SG/CE_RED certification')
    except (RequestException, ValueError, AttributeError, TypeError):
        pass

    try:
        response = post(keys_url, data='operation=read',
                        timeout=probe_timeout, verify=verify_ssl)
        data = response.json().get('data', {})
        keys = data.get('password', []) if isinstance(data, dict) else []
        if isinstance(keys, list) and len(keys) == 2:
            modulus, exponent = keys
            if (isinstance(modulus, str) and isinstance(exponent, str)
                    and all(c in '0123456789abcdefABCDEF' for c in modulus)
                    and all(c in '0123456789abcdefABCDEF' for c in exponent)
                    and exponent and int(exponent, 16) >= 3):
                if len(modulus) == 512:
                    return DetectionResult('TplinkRouterV1_11', 'medium',
                                           '2048-bit LuCI password RSA key')
                if len(modulus) == 256:
                    return DetectionResult('TplinkRouter', 'medium',
                                           '1024-bit LuCI password RSA key')
    except (RequestException, ValueError, AttributeError, TypeError):
        pass

    return DetectionResult(None, 'unknown', 'no uniquely recognized LuCI signature')
