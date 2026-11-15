from requests import post

from tplinkrouterc6u.client.c6u import TplinkEncryption
from tplinkrouterc6u.client.re813xe import TplinkRE813XERouter
from tplinkrouterc6u.common.dataclass import Status
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.common.helper import get_ip, get_mac


class TplinkRE235BERouter(TplinkEncryption, TplinkRE813XERouter):
    """
    TP-Link LuCI Wi-Fi extenders/APs that wrap every request in the classic
    LuCI encryption (RE235BE, …).

    The web endpoints are the same as on the RE813XE family
    (``admin/status?form=ap_status`` for Wi-Fi clients, no
    ``admin/status?form=all``), so the status, Wi-Fi and repeater methods come
    from ``TplinkRE813XERouter``. The transport is the one of ``TplinkRouter``:
    RSA login through ``login?form=keys`` / ``login?form=auth`` and AES
    ``sign`` / ``data`` bodies, with the plain password.

    The firmware answers ``400 Bad Request`` to any request without a
    ``Referer`` header, including the unauthenticated ``login?form=keys`` and
    ``login?form=auth`` reads.
    """

    def __init__(self, host: str, password: str, username: str = 'admin', logger=None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        # TplinkEncryption.__init__ runs after TplinkRE813XERouter.__init__ and
        # clears the headers, so set them again.
        referer = '{}/webpages/index.html'.format(self.host)
        self._headers_request = {'Referer': referer, 'Origin': self.host}
        self._headers_login = {'Referer': referer, 'Content-Type': 'application/x-www-form-urlencoded'}

    def supports(self) -> bool:
        """Detect the firmware by capability, as ``TplinkRE813XERouter`` does.

        The unauthenticated ``login?form=keys`` read is tried first, so a device
        without this login never gets a login attempt from this client.
        """
        if len(self.password) > 125:
            return False
        try:
            self._request_pwd()
        except ClientException:
            return False
        return TplinkRE813XERouter.supports(self)

    def authorize(self) -> None:
        # supports() keeps the session; skip re-login to avoid "user conflict".
        if self._logged and self._stok:
            return
        TplinkEncryption.authorize(self)

    def _request_pwd(self) -> None:
        data = self._read_login_form('keys', 'pwd')
        try:
            self._pwdNN, self._pwdEE = data['password'][0], data['password'][1]
        except Exception as e:
            raise self._login_form_error('pwd', e, data)

    def _request_seq(self) -> None:
        data = self._read_login_form('auth', 'seq')
        try:
            self._seq = data['seq']
            self.nn, self.ee = data['key'][0], data['key'][1]
        except Exception as e:
            raise self._login_form_error('seq', e, data)

    def _read_login_form(self, form: str, name: str) -> dict:
        response = post(
            '{}/cgi-bin/luci/;stok=/login?form={}'.format(self.host, form),
            params={'operation': 'read'},
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        try:
            return response.json()[self._data_block]
        except Exception as e:
            raise self._login_form_error(name, e, response.text)

    def _login_form_error(self, name: str, e: Exception, response) -> ClientException:
        error = ('TplinkRouter - {} - Unknown error for {}! Error - {}; Response - {}'
                 .format(self.__class__.__name__, name, e, response))
        if self._logger:
            self._logger.debug(error)
        return ClientException(error)

    def get_status(self) -> Status:
        status = TplinkRE813XERouter.get_status(self)
        # admin/network?form=lan_ipv4 has no lan_macaddr / lan_ip here;
        # admin/network?form=status_ipv4 has both.
        if status._lan_macaddr is None or status._lan_ipv4_addr is None:
            try:
                lan = self.request('admin/network?form=status_ipv4', 'operation=read') or {}
            except ClientError:
                lan = {}
            if status._lan_macaddr is None and lan.get('lan_macaddr'):
                status._lan_macaddr = get_mac(lan['lan_macaddr'])
            if status._lan_ipv4_addr is None and lan.get('lan_ipv4_ipaddr'):
                status._lan_ipv4_addr = get_ip(lan['lan_ipv4_ipaddr'])
        return status
