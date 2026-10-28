from logging import Logger
from re import search
from urllib.parse import urlencode
from requests import post
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import PortModes, Status
from tplinkrouterc6u.common.helper import get_mac
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client.c6u import TplinkBaseRouter


class TplinkC5400XRouter(TplinkBaseRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        # This firmware ignores the POST body without a form Content-Type: insert/remove fail with
        # "no such callback" and write parameters (e.g. enable=on) are dropped
        self._headers_request['Content-Type'] = 'application/x-www-form-urlencoded'
        self._traffic_lists = True

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

    def get_status(self) -> Status:
        status = super().get_status()
        if not self._traffic_lists:
            return status
        try:
            rows = self.request('admin/traffic?form=lists&operation=load', 'operation=load')
        except Exception:
            self._traffic_lists = False
            return status

        # There is no game_accelerator list here; the Traffic Monitor page's list has, per MAC and IP (rows of
        # old IPs stay), the live bytes/s the client receives (rerx_byte) and sends (retx_byte) and its total_byte.
        # It counts internet traffic (checked against a ~90 Mbit/s download) and traffic between local clients
        traffic = {}
        rows = rows if isinstance(rows, list) else []
        status.clients_down_speed = sum(int(row.get('rerx_byte') or 0) for row in rows)
        status.clients_up_speed = sum(int(row.get('retx_byte') or 0) for row in rows)
        for row in rows:
            if not row.get('mac'):
                continue
            mac = str(get_mac(row['mac']))
            down, up, total = traffic.get(mac, (0, 0, 0))
            traffic[mac] = (down + int(row.get('rerx_byte') or 0), up + int(row.get('retx_byte') or 0),
                            total + int(row.get('total_byte') or 0))
        for device in status.devices:
            if device.macaddr in traffic and device.down_speed is None:
                device.down_speed, device.up_speed, device.traffic_usage = traffic[device.macaddr]

        return status

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

    def get_port_modes(self) -> PortModes:
        wan = self.request('admin/network?form=addl_wan&operation=read', 'operation=read')
        lan = self.request('admin/network?form=lan_agg&operation=read', 'operation=read')
        iptv = self.request('admin/iptv?form=setting&operation=read', 'operation=read')
        return PortModes(
            wan_aggregation={'1': True, '0': False}.get(str(wan.get('addl_wan_enable'))),
            link_aggregation={'1': True, '0': False}.get(str(lan.get('enable_agg'))),
            iptv={'on': True, 'off': False}.get(iptv.get('enable')),
        )

    def nat_boost_status(self) -> bool | None:
        # Hardware NAT acceleration (System Parameters). While it is off the Traffic Monitor counters see every
        # client's traffic; None when the firmware has no NAT Boost
        data = self.request('admin/nat?form=setting&operation=read', 'operation=read')
        if data.get('boost_support') != 'yes':
            return None
        return {'on': True, 'off': False}.get(data.get('hw_enable'))

    def smart_connect_status(self) -> bool | None:
        data = self.request('admin/wireless?form=smart_connect&operation=read', 'operation=read')
        return {'on': True, 'off': False}.get(data.get('smart_enable'))

    def set_smart_connect(self, enable: bool) -> None:
        self.request('admin/wireless?form=smart_connect',
                     'operation=write&smart_enable={}'.format('on' if enable else 'off'))
        if not enable:
            return
        # Like the web page: Smart Connect is one network on every band, so the 5 GHz bands get the 2.4 GHz
        # name and security. Turning it off does not bring their old settings back.
        data = self.request('admin/wireless?form=wireless_2g', 'operation=read')
        values = {}
        for key in ('enable', 'ssid', 'hidden', 'encryption', 'psk_version', 'psk_cipher', 'psk_key', 'disabled_all'):
            value = data.get('wireless_2g_' + key, data.get(key))
            if value is not None:
                values['wireless_5g_' + key] = value
                values['wireless_5g_2_' + key] = value
        self.request('admin/wireless?form=wireless_5g&form=wireless_5g_2', urlencode({'operation': 'write', **values}))

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
