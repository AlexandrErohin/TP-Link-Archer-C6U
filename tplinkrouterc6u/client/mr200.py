import base64
from tplinkrouterc6u.client.mr import TPLinkMRClient
from Crypto.PublicKey import RSA
from binascii import hexlify
from Crypto.Cipher import PKCS1_v1_5
from re import search
from tplinkrouterc6u.common.package_enum import VPN
from tplinkrouterc6u.common.dataclass import (
    LTEStatus,
    VPNStatus,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError, AuthorizeError


class TPLinkMR200Client(TPLinkMRClient):

    def supports(self) -> bool:
        try:
            self._get_params()
            return True
        except ClientException:
            return False

    def authorize(self) -> None:
        self._get_params()

        # Construct the RSA public key manually using modulus (n) and exponent (e)
        pub_key = RSA.construct((self._nn, self._ee))

        # Create an RSA cipher with PKCS#1 v1.5 padding (same as rsa.encrypt)
        cipher = PKCS1_v1_5.new(pub_key)

        # Encrypt username
        rsa_username = cipher.encrypt(self.username.encode("utf-8"))
        rsa_username_hex = hexlify(rsa_username).decode("utf-8")

        # Encrypt password (after base64 encoding, as in your original code)
        rsa_password = cipher.encrypt(base64.b64encode(self.password.encode("utf-8")))
        rsa_password_hex = hexlify(rsa_password).decode("utf-8")

        # Send login request
        self.req.post(
            f'{self.host}/cgi/login?UserName={rsa_username_hex}&Passwd={rsa_password_hex}&Action=1&LoginStatus=0'
        )

        # Try to extract token
        r = self.req.get(self.host)
        try:
            self.req.headers["TokenID"] = search(r'var token="(.*)";', r.text).group(1)
        except AttributeError:
            raise AuthorizeError()

    def get_vpn_status(self) -> VPNStatus:
        status = VPNStatus()
        acts = [
            self.ActItem(self.ActItem.GL, 'IPSEC_CFG'),
        ]
        _, values = self.req_act(acts)

        status.ipsecvpn_enable = values.get('enable') == '1'

        return status

    def set_vpn(self, vpn: VPN, enable: bool) -> None:
        acts = [
            self.ActItem(
                self.ActItem.SET,
                'IPSEC_CFG',
                '1,0,0,0,0,0',
                attrs=['enable={}'.format(int(enable))]
            )
        ]

        self.req_act(acts)

    def logout(self) -> None:
        acts = [
            self.ActItem(self.ActItem.CGI, '/cgi/logout')
        ]

        response, _ = self.req_act(acts)
        ret_code = self._parse_ret_val(response.text)

        if ret_code == self.HTTP_RET_OK:
            del self.req.headers["TokenID"]

    def get_lte_status(self) -> LTEStatus:
        status = LTEStatus()
        acts = [
            self.ActItem(self.ActItem.GET, 'WAN_LTE_LINK_CFG', '2,1,0,0,0,0',
                         attrs=['enable', 'connectStatus', 'networkType', 'roamingStatus', 'simStatus']),
            self.ActItem(self.ActItem.GET, 'WAN_LTE_INTF_CFG', '2,0,0,0,0,0',
                         attrs=['dataLimit', 'enablePaymentDay', 'curStatistics', 'totalStatistics', 'enableDataLimit',
                                'limitation',
                                'curRxSpeed', 'curTxSpeed']),
            self.ActItem(self.ActItem.GET, 'LTE_WAN_CFG', '2,1,0,0,0,0'),
        ]
        _, values = self.req_act(acts)

        status.enable = values['0'].get('enable', 0)
        status.connect_status = values['0'].get('connectStatus', 0)
        status.network_type = values['0'].get('networkType', 0)
        status.sim_status = values['0'].get('simStatus', 0)
        status.sig_level = values['0'].get('signalStrength', 0)

        status.total_statistics = values['1'].get('totalStatistics', 0)
        status.cur_rx_speed = values['1'].get('curRxSpeed', 0)
        status.cur_tx_speed = values['1'].get('curTxSpeed', 0)

        status.isp_name = values['2'].get('profileName', '')

        sms_list = self.get_sms()
        status.sms_unread_count = sum(1 for m in sms_list if getattr(m, 'unread', False))

        return status

    def _get_params(self, retry=False) -> None:
        self.req.headers = {'referer': f'{self.host}/', 'origin': self.host}
        try:
            r = self.req.get(f"{self.host}/cgi/getParm", timeout=5)
            result = {}
            for line in r.text.splitlines()[0:2]:
                match = search(r"var (.*)=\"(.*)\"", line)
                result[match.group(1)] = int(match.group(2), 16)

            self._nn = int(result["nn"])
            self._ee = int(result["ee"])
        except Exception as e:
            if not retry:
                self._get_params(True)
            raise ClientException(str(e))

    def req_act(self, acts: list):
        '''
        Requests ACTs via the cgi_gdpr proxy
        '''
        act_types = []
        act_data = []

        for act in acts:
            act_types.append(str(act.type))
            act_data.append('[{}#{}#{}]{},{}\r\n{}\r\n'.format(
                act.oid,
                act.stack,
                act.pstack,
                len(act_types) - 1,  # index, starts at 0
                len(act.attrs),
                '\r\n'.join(act.attrs)
            ))

        data = ''.join(act_data)
        url = f"{self.host}/cgi?" + '&'.join(act_types)
        response = self.req.post(url, data=data)
        code = response.status_code

        if code != 200:
            error = 'TplinkRouter - MR200 -  Response with error; Request {} - Response {}'.format(data, response.text)
            if self._logger:
                self._logger.debug(error)
            raise ClientError(error)

        # Convert Response to string for _merge_response
        result = self._merge_response(response.text)

        return response, result.get('0') if len(result) == 1 and result.get('0') else result
