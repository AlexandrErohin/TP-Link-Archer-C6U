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

    This deliberately covers only SG, AX72, V1_11 and classic LuCI. A UI skin
    or an unsuccessful probe is not enough to guess another model's auth
    mode. Key sizes are medium-confidence fingerprints, not proof of a
    signing scheme; anything ambiguous is left unresolved.

    SG and AX72 both serve a 512-bit auth key, so AX72 is selected only when
    device_config was read successfully and did not report an SG/CE_RED
    certification. A failed config probe plus a 512-bit auth key stays
    unresolved rather than guessing.
    """
    if not host.startswith(('http://', 'https://')):
        host = 'http://' + host
    host = host.rstrip('/')
    # Keep passive checks bounded even if the main client timeout is large.
    probe_timeout = min(timeout, 5) if isinstance(timeout, (int, float)) else timeout
    config_url = host + '/cgi-bin/luci/;stok=/device_config?form=config'
    keys_url = host + '/cgi-bin/luci/;stok=/login?form=keys'
    auth_url = host + '/cgi-bin/luci/;stok=/login?form=auth'

    # Mirrors TplinkRouterSG._check_sg_certification, including the Referer
    # and Content-Type headers TplinkBaseRouter sets for login requests:
    # without them this firmware answers "no such callback" and an SG router
    # would fall through to the password-key classification below.
    config_ok = False
    try:
        response = post(config_url, data='operation=read',
                        headers={'Referer': host + '/webpages/index.html',
                                 'Content-Type': 'application/x-www-form-urlencoded'},
                        timeout=probe_timeout, verify=verify_ssl)
        data = response.json().get('data', {})
        certs = data.get('certification', []) if isinstance(data, dict) else []
        config_ok = True
        if isinstance(certs, list) and any(c in SG_CERTIFICATIONS for c in certs):
            return DetectionResult('TplinkRouterSG', 'high', 'SG/CE_RED certification')
    except (RequestException, ValueError, AttributeError, TypeError):
        pass

    # A 512-bit auth key is also served by SG (e.g. Archer AX12 / AX23). Only
    # treat it as AX72 when device_config was readable and was not SG/CE_RED;
    # otherwise leave unresolved so get_client_safe does not burn a wrong login.
    try:
        response = post(auth_url, params={'operation': 'read'},
                        timeout=probe_timeout, verify=verify_ssl)
        data = response.json().get('data', {})
        key = data.get('key', []) if isinstance(data, dict) else []
        if (isinstance(key, list) and len(key) == 2
                and isinstance(key[0], str) and len(key[0]) == 128
                and all(c in '0123456789abcdefABCDEF' for c in key[0])):
            if not config_ok:
                return DetectionResult(
                    None, 'unknown',
                    '512-bit auth key without confirmed non-SG device_config')
            return DetectionResult('TplinkRouterAX72', 'medium',
                                   '512-bit LuCI auth key')
    except (RequestException, ValueError, AttributeError, TypeError):
        pass

    # Classic and V1_11 are fingerprinted by the password key served by
    # form=keys. The V1_11 threshold mirrors its own supports() check.
    try:
        response = post(keys_url, params={'operation': 'read'},
                        timeout=probe_timeout, verify=verify_ssl)
        data = response.json().get('data', {})
        keys = data.get('password', []) if isinstance(data, dict) else []
        if isinstance(keys, list) and len(keys) == 2:
            modulus, exponent = keys
            if (isinstance(modulus, str) and isinstance(exponent, str)
                    and all(c in '0123456789abcdefABCDEF' for c in modulus)
                    and all(c in '0123456789abcdefABCDEF' for c in exponent)
                    and exponent and int(exponent, 16) >= 3):
                if len(modulus) >= 512:
                    return DetectionResult('TplinkRouterV1_11', 'medium',
                                           '≥2048-bit LuCI password RSA key')
                if len(modulus) == 256:
                    return DetectionResult('TplinkRouter', 'medium',
                                           '1024-bit LuCI password RSA key')
    except (RequestException, ValueError, AttributeError, TypeError):
        pass

    return DetectionResult(None, 'unknown', 'no uniquely recognized LuCI signature')
