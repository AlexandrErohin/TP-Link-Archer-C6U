"""
TP-Link Archer VR400 v2 Client

Based on reverse-engineering of network traffic.
Protocol is similar to MR series but with differences in:
1. Login: Uses RSA encryption (PKCS1 v1.5) for both Username and Password
2. Password must be Base64 encoded before encryption
3. Actions: Uses /cgi endpoint with types in query string and plain text body
"""

from re import search, findall
from logging import Logger

from tplinkrouterc6u.client.mr200 import TPLinkMR200Client
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.common.dataclass import VPNStatus


class TPLinkVR400v2Client(TPLinkMR200Client):
    """Client for TP-Link Archer VR400 v2"""

    def __init__(self, host: str, password: str, username: str = '', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30):
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self.req.headers['User-Agent'] = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        )

    def supports(self) -> bool:
        """
        Detect VR400 v2 by checking for 'userSetting' variable in /cgi/getParm response.
        This distinguishes VR400v2 from standard MR200 routers.
        """
        try:
            self._get_params()
            # After successful parameter fetch, check for VR400v2-specific signature
            r = self.req.get(f"{self.host}/cgi/getParm", timeout=5)
            if 'var userSetting' in r.text:
                return True
        except Exception:
            pass

        return False

    def _get_params(self, retry=False) -> None:
        """
        Override to handle VR400v2's response format with extra variables and semicolons.
        Uses findall to parse entire response instead of just first 2 lines.
        """
        self.req.headers = {'referer': f'{self.host}/', 'origin': self.host}
        try:
            r = self.req.get(f"{self.host}/cgi/getParm", timeout=5)
            matches = findall(r'var\s+(.*?)\s*=\s*"(.*?)"', r.text)
            result = {}
            for key, val in matches:
                result[key] = int(val, 16)

            self._nn = int(result["nn"])
            self._ee = int(result["ee"])
        except Exception as e:
            if not retry:
                self._get_params(True)
            raise ClientException(str(e))

    def _req_token(self):
        """Token extraction handled by parent's authorize() method."""
        pass

    def _parse_ret_val(self, response_text):
        """Parse return code from VR400v2 response (supports multiple formats)."""
        # Try $.ret=...; format
        result = search(r'\$\.ret=([-]?\d+);', response_text)
        if result:
            return int(result.group(1))

        # Try [error]... format
        result = search(r'\[error\](\d+)', response_text)
        if result:
            return int(result.group(1))

        # Try var errorcode=... format
        result = search(r'var\s+errorcode\s*=\s*(\d+)', response_text)
        if result:
            return int(result.group(1))

        if '[error]0' in response_text or 'errorcode=0' in response_text:
            return 0

        if self._logger:
            self._logger.debug(f"Could not parse return code from: {response_text[:100]}...")

    def get_vpn_status(self) -> VPNStatus:
        status = VPNStatus()
        acts = [
            self.ActItem(self.ActItem.GET, 'OPENVPN', attrs=['enable']),
            self.ActItem(self.ActItem.GET, 'PPTPVPN', attrs=['enable']),
            self.ActItem(self.ActItem.GL, 'OVPN_CLIENT', attrs=['connAct']),
            self.ActItem(self.ActItem.GL, 'PVPN_CLIENT', attrs=['connAct']),
        ]
        _, values = self.req_act(acts)

        status.openvpn_enable = values['0']['enable'] == '1'
        status.pptpvpn_enable = values['1']['enable'] == '1'

        for item in values['2']:
            if item['connAct'] == '1':
                status.openvpn_clients_total += 1

        for item in values['3']:
            if item['connAct'] == '1':
                status.pptpvpn_clients_total += 1

        return status
