import base64
import re
from time import sleep
from urllib.parse import urlparse

import requests
from requests import Response

from tplinkrouterc6u.client.mr200 import TPLinkMR200Client
from tplinkrouterc6u.common.package_enum import VPN
from tplinkrouterc6u.common.dataclass import (
    LTEStatus,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.common.package_enum import Connection


class TplinkC3200Router(TPLinkMR200Client):
    # This is a session variable that will contain everything needed as soon as the router is connected.
    #  - The "Referer" header which allows to be accepted by the CGI module.
    # - the Authentification cookie
    SESSION: requests.Session

    # Possible retries limit
    REQUEST_RETRIES = 1

    # Router name to be included in logs for example,
    # or to be redefined by subclasses.
    ROUTER_NAME = "TP Link Router C3200"

    # Connection method
    def supports(self) -> bool:
        if len(self.password) > 125:
            return False

        try:
            # This method checks if we can recognize the router type.
            welcome_page = requests.get(self.host, timeout=5)
            if welcome_page and welcome_page.status_code == 200 and re.search("Archer", welcome_page.text):
                return True
        except ClientException:
            pass

        return False

    def authorize(self) -> None:

        # ———————————————————————————————————————————
        # Create the SESSION object and the authorization cookie
        # ———————————————————————————————————————————
        self.SESSION = requests.Session()

        if self._logger:
            self._logger.debug("!")
        # We need to extract the domain form the host to fill the cookie.
        router_host = urlparse(self.host).hostname
        if not router_host:
            raise ValueError(self.host & " must contain a valid host, ex. http://192.168.168.1")

        """Return the string "Basic <base64(username:password)>"."""
        token_bytes = f"{self.username}:{self.password}".encode()
        encoded = base64.b64encode(token_bytes).decode()
        auth_cookie_value = f"Basic {encoded}"

        self.SESSION.cookies.set(
            name="Authorization",
            value=auth_cookie_value,
            domain=router_host,
            path="/",
        )

        self.SESSION.headers = {"Referer": f"{self.host}/", "Origin": self.host}

        login_url = '{}/'.format(self.host)
        response = Response()

        try:
            response = self.SESSION.post(login_url, timeout=10)
        except Exception as e:
            error = self.ROUTER_NAME + " - Cannot authorize! Error - {}; Response - {}".format(e, response.text)
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def logout(self) -> None:
        self.SESSION.cookies.clear(domain=urlparse(self.host).hostname, path="/")

    def get_lte_status(self) -> LTEStatus:
        pass

    def _get_params(self, retry=False) -> None:
        pass

    def set_vpn(self, vpn: VPN, enable: bool) -> None:
        # Unable to test it on my C3200
        pass

    def req_act(self, acts: list):
        act_types, act_data = self._fill_acts(acts)

        url = f"{self.host}/cgi?" + '&'.join(act_types)
        data_str = ''.join(act_data)
        (code, response) = self._request(url, data_str=data_str)

        if code != 200:
            error = self.ROUTER_NAME + ' -  Response with error; Request {} - Response {}'.format(data_str, response)
            if self._logger:
                self._logger.debug(error)
            raise ClientError(error)

        result = self._merge_response(response)

        return response, result.get('0') if len(result) == 1 and result.get('0') else result

    def _request(self, url, method='POST', data_str=None, encrypt=False, is_login=False):
        r = Response()

        retry = 0
        while retry < self.REQUEST_RETRIES:
            # send the request
            if method == 'POST':
                r = self.SESSION.post(url, data=data_str)
            elif method == 'GET':
                r = self.SESSION.get(url, data=data_str)
            else:
                raise Exception('Unsupported method ' + str(method))

            # sometimes we get 500 here, not sure why... just retry the request
            if (r.status_code not in [500, 406]
                    and '<title>500 Internal Server Error</title>' not in r.text
                    and '<title>406 Not Acceptable</title>' not in r.text):
                break

            sleep(0.1)
            retry += 1

        return r.status_code, r.text

    # Overriding the method since we have two 5G bands in the rooter.
    # We manage both as one.
    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        acts = []

        match wifi:
            case Connection.HOST_2G:
                acts = [
                    self.ActItem(
                        self.ActItem.SET,
                        'LAN_WLAN',
                        '1,1,0,0,0,0',
                        attrs=['enable={}'.format(int(enable))]),
                ]
            case Connection.HOST_5G:
                # We activate both 5G bands
                acts = [
                    self.ActItem(
                        self.ActItem.SET,
                        'LAN_WLAN',
                        '1,2,0,0,0,0',
                        attrs=['enable={}'.format(int(enable))]),
                    self.ActItem(
                        self.ActItem.SET,
                        'LAN_WLAN',
                        '1,3,0,0,0,0',
                        attrs=['enable={}'.format(int(enable))]),
                ]
            case Connection.GUEST_2G:
                acts = [
                    self.ActItem(
                        self.ActItem.SET,
                        'LAN_WLAN_MSSIDENTRY',
                        '1,1,1,0,0,0',
                        attrs=['enable={}'.format(int(enable))]),
                ]
            case Connection.GUEST_5G:
                acts = [
                    self.ActItem(
                        self.ActItem.SET,
                        'LAN_WLAN_MSSIDENTRY',
                        '1,2,1,0,0,0',
                        attrs=['enable={}'.format(int(enable))]),
                    self.ActItem(
                        self.ActItem.SET,
                        'LAN_WLAN_MSSIDENTRY',
                        '1,3,1,0,0,0',
                        attrs=['enable={}'.format(int(enable))]),
                ]
        self.req_act(acts)

    def reboot(self) -> None:
        # CGI 7 et [ACT_REBOOT#0,0,0,0,0,0#0,0,0,0,0,0]0,0

        acts = [
            self.ActItem(self.ActItem.OP, 'ACT_REBOOT'),
        ]
        _, values = self.req_act(acts)

        # print(values.keys())
