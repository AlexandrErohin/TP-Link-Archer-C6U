# Tested on:
#   TL-WR841N v14  - Firmware 0.9.1 4.17 v0348.0 Build 200114 Rel.64471n

"""
Clients for TP-Link routers that use GDPR-encrypted CGI auth (/cgi_gdpr).

These devices share a common protocol:
  - Login/data: POST /cgi_gdpr  with  sign=<RSA>\r\ndata=<AES-128-CBC>\r\n
  - RSA key: 512-bit, fetched from /cgi/getParm
  - AES session parameters are established at login and reused for all requests

Two RSA variants exist, distinguished by the `flag` value in tpEncrypt.js:

  flag=0  Raw RSA (left-justified), 64-byte chunks → TPLinkWR841NClient (TL-WR841N)
"""

from __future__ import annotations

import re
from datetime import datetime
from random import randint
from time import time
from requests import Session

from tplinkrouterc6u.client.c50 import TPLinkC50Client
from tplinkrouterc6u.common.exception import AuthorizeError, ClientException


class TPLinkWR841NClient(TPLinkC50Client):
    """
    Client for GDPR-encrypted routers using raw RSA (flag=0, 512-bit key).

    These routers share the /cgi_gdpr + AES-128-CBC protocol with the C50
    family but use raw RSA (no PKCS#1 v1.5 padding) for the sign field:
      - tpEncrypt.js: $.rsa.encrypt(..., 512, 0)  ← flag=0
      - Block size: 64 bytes (full 512-bit key, no padding overhead)

    Tested on: TL-WR841N v14
    """

    ROUTER_NAME = "TP-Link TL-WR841N"

    # Raw RSA: full 64-byte block (no PKCS#1 overhead)
    _RSA_CHUNK = 64

    def supports(self) -> bool:
        """
        Return True for GDPR-encrypted routers with a 512-bit key and raw
        RSA (flag=0): INCLUDE_LOGIN_GDPR_ENCRYPT=1 and "512,0" in tpEncrypt.js.
        """
        try:
            nn, _ee, _seq = self._fetch_rsa_key()
            if len(nn) != self._RSA_KEY_HEX_LEN:
                return False

            r = self._session.get(
                f"{self.host}/js/oid_str.js",
                headers=self._base_headers(),
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if not (r.status_code == 200 and "INCLUDE_LOGIN_GDPR_ENCRYPT=1" in r.text):
                return False

            r2 = self._session.get(
                f"{self.host}/js/tpEncrypt.js",
                headers=self._base_headers(),
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            return r2.status_code == 200 and "512,0" in r2.text
        except Exception:
            return False

    def authorize(self) -> None:
        """Override to perform GET / before login — required by TL-WR841N."""
        # Start with a clean HTTP session
        self._session = Session()
        if not self._verify_ssl:
            self._session.verify = False

        # TL-WR841N requires a GET / before login to establish a valid
        # server-side session; without it the login POST returns HTTP 500.
        self._session.get(
            self.host + "/",
            headers={
                "Accept": "text/html,application/xhtml+xml,*/*",
                "User-Agent": self._base_headers()["User-Agent"],
                "Referer": self._base_headers()["Referer"],
            },
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        # Now proceed with the standard C50 login flow
        nn, ee, seq = self._fetch_rsa_key()

        ts = str(round(time() * 1000))
        aes_key = (ts + str(randint(100_000_000, 999_999_999)))[:16]
        aes_iv = (ts + str(randint(100_000_000, 999_999_999)))[:16]
        pw_hash = self._hash

        login_plain = (
            f"8\r\n"
            f"[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\n"
            f"username={self.username}\r\n"
            f"password={self.password}\r\n"
        )

        enc_data = self._aes_enc(login_plain, aes_key, aes_iv)
        sign = self._make_sign(
            seq + len(enc_data),
            is_login=True,
            pw_hash=pw_hash,
            nn=nn,
            ee=ee,
            aes_key=aes_key,
            aes_iv=aes_iv,
        )

        body = f"sign={sign}\r\ndata={enc_data}\r\n"
        response = self._session.post(
            f"{self.host}/cgi_gdpr",
            headers=self._base_headers(),
            data=body,
            timeout=self.timeout,
            stream=True,
        )
        raw = self._read_chunked(response)

        if self._logger:
            self._logger.debug(
                "%s - authorize: HTTP %s raw_len=%s",
                self.ROUTER_NAME, response.status_code, len(raw),
            )

        if response.status_code != 200:
            raise ClientException(
                f"{self.ROUTER_NAME} - authorize: HTTP {response.status_code}"
            )

        try:
            decrypted = self._aes_dec(raw, aes_key, aes_iv)
        except Exception as exc:
            raise ClientException(
                f"{self.ROUTER_NAME} - authorize: AES decrypt failed: {exc}"
            ) from exc

        if "$.ret=0" not in decrypted:
            ret_match = re.search(r"\$\.ret=(\d+)", decrypted)
            ret_code = int(ret_match.group(1)) if ret_match else -1
            if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
                raise AuthorizeError(
                    f"{self.ROUTER_NAME} - Login failed: wrong password"
                )
            raise ClientException(
                f"{self.ROUTER_NAME} - Login failed. Error code: {ret_code}"
            )

        # Post-login GET / to complete session initialisation.
        self._session.get(
            self.host + "/",
            headers={
                "Accept": "text/html,application/xhtml+xml,*/*",
                "User-Agent": self._base_headers()["User-Agent"],
                "Referer": self._base_headers()["Referer"],
            },
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        self._login_nn = nn
        self._login_ee = ee
        self._login_seq = seq
        self._aes_key = aes_key
        self._aes_iv = aes_iv
        self._token = "wr841n_session"  # sentinel so base-class guards pass
        self._authorized_at = datetime.now()

    @staticmethod
    def _rsa_pkcs_encrypt(data: str, nn: str, ee: str) -> str:
        """
        Raw RSA encryption (no padding) — flag=0, 512-bit key.

        TP-Link left-justifies the plaintext in the block (data bytes first,
        trailing zero-padding).  This differs from PKCS#1 v1.5 which
        right-justifies with a structured padding prefix.
        """
        n = int(nn, 16)
        e = int(ee, 16)
        block_size = (n.bit_length() + 7) // 8  # 64 bytes for a 512-bit key
        m_bytes = data.encode("utf-8").ljust(block_size, b"\x00")
        m = int.from_bytes(m_bytes, "big")
        c = pow(m, e, n)
        return hex(c)[2:].zfill(block_size * 2)
