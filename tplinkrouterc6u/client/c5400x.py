from logging import Logger
from re import search
from requests import post
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client.c6u import TplinkBaseRouter


class TplinkC5400XRouter(TplinkBaseRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        # This firmware ignores the POST body without a form Content-Type: insert/remove fail with
        # "no such callback" and write parameters (e.g. enable=on) are dropped
        self._headers_request['Content-Type'] = 'application/x-www-form-urlencoded'

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        # Once the body is read, a parameter that is also in the URL arrives twice ("no such callback" for
        # operation): send it only in the body, like the web UI
        if data and '?' in path:
            base, query = path.split('?', 1)
            sent = {pair.split('=', 1)[0] for pair in data.split('&')}
            query = '&'.join(pair for pair in query.split('&') if pair.split('=', 1)[0] not in sent)
            path = '{}?{}'.format(base, query) if query else base
        return super().request(path, data, ignore_response, ignore_errors)

    def supports(self) -> bool:
        return len(self.password) >= 200

    def authorize(self) -> None:
        if len(self.password) < 200:
            raise Exception('You need to use web encrypted password instead. Check the documentation!')

        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        response = post(
            url,
            params={'operation': 'login', 'username': self.username, 'password': self.password},
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            self._stok = response.json().get('data').get('stok')
            regex_result = search('sysauth=(.*);', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._logged = True

        except Exception as e:
            error = "TplinkRouter - C5400X - Cannot authorize! Error - {}; Response - {}".format(e, response.text)
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _status_conn_type(self, data: dict) -> str | None:
        # conn_type here is the USB modem connection ("0" = none); the WAN type is wan_ipv4_conntype
        return data.get('wan_ipv4_conntype') or data.get('conn_type')

    def set_led(self, enable: bool) -> None:
        current_state = (self.request('admin/ledgeneral?form=setting&operation=read', 'operation=read')
                         .get('enable', 'off') == 'on')
        if current_state != enable:
            self.request('admin/ledgeneral?form=setting&operation=write',
                         'operation=write&enable={}'.format('on' if enable else 'off'))

    def led_status(self) -> bool | None:
        return self.get_led()

    def get_led(self) -> bool | None:

        data = self.request('admin/ledgeneral?form=setting&operation=read', 'operation=read')
        led_status = data.get('enable') if 'enable' in data else None
        if led_status == 'on':
            return True
        elif led_status == 'off':
            return False
        else:
            return None

    def led_night_mode_status(self) -> bool | None:
        data = self.request('admin/ledpm?form=setting&operation=read', 'operation=read')
        return {'on': True, 'off': False}.get(data.get('enable'))

    def set_led_night_mode(self, enable: bool) -> None:
        # Only enable: the router keeps time_start / time_end as they are
        self.request('admin/ledpm?form=setting&operation=write',
                     'operation=write&enable={}'.format('on' if enable else 'off'))

    def set_wifi(self, wifi: Connection, enable: bool = None, ssid: str = None, hidden: str = None,
                 encryption: str = None, psk_version: str = None, psk_cipher: str = None, psk_key: str = None,
                 hwmode: str = None, htmode: str = None, channel: int = None, txpower: str = None,
                 disabled_all: str = None) -> None:
        values = {
            Connection.HOST_2G: 'wireless_2g',
            Connection.HOST_5G: 'wireless_5g',
            Connection.HOST_5G_2: 'wireless_5g_2',
            Connection.HOST_6G: 'wireless_6g',
            Connection.GUEST_2G: 'guest_2g',
            Connection.GUEST_5G: 'guest_5g',
            Connection.GUEST_5G_2: 'guest_5g_2',
            Connection.GUEST_6G: 'guest_6g',
            Connection.IOT_2G: 'iot_2g',
            Connection.IOT_5G: 'iot_5g',
            Connection.IOT_6G: 'iot_6g',
        }

        value = values.get(wifi)
        if not value:
            raise ValueError(f"Invalid Wi-Fi connection type: {wifi}")

        if all(v is None for v in [enable, ssid, hidden, encryption, psk_version, psk_cipher, psk_key, hwmode,
                                   htmode, channel, txpower, disabled_all]):
            raise ValueError("At least one wireless setting must be provided")

        data = "operation=write"

        if enable is not None:
            data += f"&enable={'on' if enable else 'off'}"
        if ssid is not None:
            data += f"&ssid={ssid}"
        if hidden is not None:
            data += f"&hidden={hidden}"
        if encryption is not None:
            data += f"&encryption={encryption}"
        if psk_version is not None:
            data += f"&psk_version={psk_version}"
        if psk_cipher is not None:
            data += f"&psk_cipher={psk_cipher}"
        if psk_key is not None:
            data += f"&psk_key={psk_key}"
        if hwmode is not None:
            data += f"&hwmode={hwmode}"
        if htmode is not None:
            data += f"&htmode={htmode}"
        if channel is not None:
            data += f"&channel={channel}"
        if txpower is not None:
            data += f"&txpower={txpower}"
        if disabled_all is not None:
            data += f"&disabled_all={disabled_all}"

        self.request(f"admin/wireless?form={value}", data)
