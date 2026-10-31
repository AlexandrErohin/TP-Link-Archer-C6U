from collections import Counter
from json import dumps, loads
from datetime import datetime, timezone
from logging import Logger
from re import IGNORECASE, fullmatch, search
from urllib.parse import quote, urlencode
from requests import post
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import (
    BlockedThreats,
    ClientsPerBand,
    DailyTraffic,
    FirmwareUpdate,
    GuestNetworkAccess,
    HomeCareStatus,
    IpMacBinding,
    PortModes,
    PortStatus,
    QoSSettings,
    RebootSchedule,
    RouterTime,
    SecuritySettings,
    SpeedTest,
    Status,
    SystemLog,
    UsbSharing,
    UsbStorage,
    VpnServerSettings,
    WanPortSpeed,
    WanSpeed,
    WifiNetwork,
    WifiOffPeriod,
    WifiSchedule,
)
from tplinkrouterc6u.common.helper import get_mac
from tplinkrouterc6u.common.exception import ClientError, ClientException
from tplinkrouterc6u.client.c6u import TplinkBaseRouter

_SECURITY_FLAGS = {'on': True, 'enable': True, 'off': False, 'disable': False}


def _security_flag(data: dict | None, key: str) -> bool | None:
    # on/off and enable/disable fields; None when missing or unknown
    if not isinstance(data, dict):
        return None
    return _SECURITY_FLAGS.get(str(data.get(key)).lower())


def _security_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _security_time(value) -> datetime | None:
    # Epoch seconds, as the web page reads them (new Date(time * 1000))
    seconds = _security_int(value)
    return datetime.fromtimestamp(seconds, timezone.utc) if seconds else None


def _security_rows(data) -> list | None:
    # A list answer; an empty one may come as {}. None when the read failed
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return [] if data == {} else None


def _flag(value) -> bool | None:
    # 'on' / 'off' in most forms; JSON true / false in wireless_schedule_wifi_disable
    if isinstance(value, bool):
        return value
    return {'on': True, 'off': False, 'true': True, 'false': False}.get(str(value).lower())


def _dict(data) -> dict:
    return data if isinstance(data, dict) else {}


def _number(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rate(value) -> int | None:
    # -1 (or anything negative) = not measured yet
    number = _number(value)
    return None if number is None or number < 0 else number


def _mbit(value) -> float | None:
    # Speed test and QoS bandwidths come in Mbit/s x 1024 (1000 Mbit/s = 1024000); the web page divides by 1024
    number = _rate(value)
    return None if number is None else number / 1024


def _epoch(value) -> datetime | None:
    # Unix time; 0 = never
    seconds = _number(value)
    if not seconds or seconds < 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# Day names of the Wireless Schedule page, in its order
WIFI_DAYS = ('sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat')


def _wifi_off_periods(entries) -> list[WifiOffPeriod] | None:
    # "days:[from,to]" strings; "eve" = every day. Entries this code cannot read are left out
    if isinstance(entries, dict) and not entries:
        return []
    if not isinstance(entries, list):
        return None
    periods = []
    for entry in entries:
        days, _, hours = str(entry).partition(':')
        try:
            start, end = loads(hours)
            start, end = int(start), int(end)
        except (TypeError, ValueError):
            continue
        periods.append(WifiOffPeriod(start=start, end=end,
                                     days=[] if days == 'eve' else [day for day in days.split(',') if day]))
    return periods


class TplinkC5400XRouter(TplinkBaseRouter):
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        # This firmware ignores the POST body without a form Content-Type: insert/remove fail with
        # "no such callback" and write parameters (e.g. enable=on) are dropped
        self._headers_request['Content-Type'] = 'application/x-www-form-urlencoded'
        self._traffic_lists = True
        self._last_status = None

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
        self._last_status = status
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

    @staticmethod
    def _map_wire_type(data: str | None, host: bool = True) -> Connection:
        # The router's own pages call the second 5 GHz band "5G_2"; the base mapping folds it into 5G
        if data and data.upper().startswith('5G') and data.replace('-', '_').endswith('_2'):
            return Connection.HOST_5G_2 if host else Connection.GUEST_5G_2
        return TplinkBaseRouter._map_wire_type(data, host)

    def get_clients_per_band(self) -> ClientsPerBand:
        # Counted from the client list of the last get_status() (no request of its own; it calls get_status() only
        # when there is none yet). Main and guest networks together; wifi_5g_2 is None without a second 5 GHz band
        status = self._last_status if self._last_status is not None else self.get_status()
        types = [device.type for device in status.devices]
        return ClientsPerBand(
            wired=types.count(Connection.WIRED),
            wifi_2g=types.count(Connection.HOST_2G) + types.count(Connection.GUEST_2G),
            wifi_5g=types.count(Connection.HOST_5G) + types.count(Connection.GUEST_5G),
            wifi_5g_2=(types.count(Connection.HOST_5G_2) + types.count(Connection.GUEST_5G_2)
                       if status.wifi_5g_2_enable is not None else None),
        )

    def get_daily_traffic(self) -> DailyTraffic:
        # What the Traffic Monitor chart shows (also while the monitor is off): bytes per day of every client together,
        # internet plus traffic between local clients. data has max_recent_tick (7) days; tick counts the days so far
        # and the chart draws only that many. The router's chart draws data[0] as the newest day and data[i] as i days
        # before it; only data[0] was seen growing during a day (when the day starts is not verified)
        data = self.request('admin/traffic?form=data&operation=seg_get', 'operation=seg_get&ip=all&seg_type=day')
        data = data if isinstance(data, dict) else {}
        rows = data.get('data') if isinstance(data.get('data'), list) else []
        tick = self._to_int(data.get('tick'))
        if tick == 0:
            rows = [{'ups': 0, 'downs': 0}]
        elif tick is not None and tick > 0:
            rows = rows[:tick]
        rows = [row if isinstance(row, dict) else {} for row in rows]
        return DailyTraffic(
            downloads=[self._to_int(row.get('downs')) for row in rows],
            uploads=[self._to_int(row.get('ups')) for row in rows],
        )

    @staticmethod
    def _to_int(value) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

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

    def get_port_status(self) -> list[PortStatus]:
        # The port table of the Network Map: one row per port, the Internet port first (wan_status / wan_speed /
        # wan_duplex), then lan1_* .. lan8_*. Port 0 is the Internet port, like that table. Status words from the
        # web page: connected, unconnected (LAN) or disconnected (Internet); the speed is 0 or "" without a link.
        # A negotiated speed means the cable is linked even if the Internet port says disconnected (no internet)
        data = self.request('admin/status?form=router&operation=read', 'operation=read')
        fields = {}
        for row in data if isinstance(data, list) else [data]:
            for key, value in _dict(row).items():
                match = fullmatch(r'(wan|lan(\d+))_(status|speed|duplex)', key)
                if match:
                    fields.setdefault(int(match.group(2) or 0), {})[match.group(3)] = value
        ports = []
        for port in sorted(fields):
            speed = _number(fields[port].get('speed'))
            speed = speed if speed and speed > 0 else None
            duplex = str(fields[port].get('duplex') or '').lower()
            ports.append(PortStatus(
                port=port,
                link_up=True if speed else {'connected': True, 'unconnected': False, 'disconnected': False,
                                            'unplugged': False}.get(str(fields[port].get('status') or '').lower()),
                negotiated_speed=speed,
                negotiated_duplex=duplex if duplex in ('full', 'half') else None,
            ))
        return ports

    def get_wan_speed(self) -> WanSpeed:
        # The live internet rate on the Network Map (the page reads it every 3 s and shows value / 1024 as KB/s):
        # bytes per second, checked against a ~90 Mbit/s download. time = when the router took it
        data = _dict(self.request('admin/status?form=wan_speed&operation=read', 'operation=read'))
        return WanSpeed(download=_rate(data.get('down_speed')), upload=_rate(data.get('up_speed')),
                        time=_epoch(data.get('test_time')))

    def get_speed_test(self) -> SpeedTest:
        # Last run of the router's own speed test (Network Map > Speed Test). status: idle, down_test, up_test or
        # fail (what the web page checks). Speeds are -1 while measuring; test_time is 0 if it never ran
        data = _dict(self.request('admin/status?form=speedtest&operation=read', 'operation=read'))
        time = _epoch(data.get('test_time'))
        if time is None:
            return SpeedTest(status=data.get('status'))
        return SpeedTest(status=data.get('status'), download=_mbit(data.get('down_speed')),
                         upload=_mbit(data.get('up_speed')), time=time)

    def start_speed_test(self) -> None:
        # The "Test again" button of Network Map > Speed Test. The router downloads and uploads for a while (the
        # internet is busy meanwhile); the web page then calls get_speed_test() every few seconds in the same session
        # until status is idle or fail
        self.request('admin/status?form=speedtest', 'operation=start')

    def get_wan_port_speed(self) -> WanPortSpeed:
        # Internet port Speed & Duplex (System Parameters): "auto", "1000F", "100F"..., and the choices this router
        # offers. Probably the setting, not the negotiated link (that is port 0 of get_port_status)
        current = _dict(self.request('admin/network?form=port_speed_current&operation=read', 'operation=read'))
        supported = _dict(self.request('admin/network?form=port_speed_supported&operation=read', 'operation=read'))
        value = current.get('speed')
        match = fullmatch(r'(\d+)([FH])', str(value or '').upper())
        choices = supported.get('supported')
        return WanPortSpeed(
            value=value,
            speed=int(match.group(1)) if match else None,
            duplex={'F': 'full', 'H': 'half'}[match.group(2)] if match else None,
            auto_negotiation=True if str(value).lower() == 'auto' else False if match else None,
            supported=[str(choice) for choice in choices] if isinstance(choices, list) else [],
        )

    def get_qos(self) -> QoSSettings:
        # Whether QoS is on (qos?form=settings) and the total bandwidth it shares out (HomeCare QoS,
        # smart_network?form=dpi_qos), in Mbit/s like the web page. bandwidth_mode "auto" = from the last speed test
        settings = _dict(self.request('admin/qos?form=settings&operation=read', 'operation=read'))
        dpi = _dict(self.request('admin/smart_network?form=dpi_qos&operation=read', 'operation=read'))
        return QoSSettings(
            enabled={'on': True, 'off': False}.get(settings.get('enable')),
            mode=dpi.get('qos_mode'),
            bandwidth_mode=dpi.get('bandwidth_mode'),
            download_bandwidth=_mbit(dpi.get('downstream_bandwidth')),
            upload_bandwidth=_mbit(dpi.get('upstream_bandwidth')),
        )

    def _security_read(self, form: str, operation: str = 'read') -> dict | list | None:
        # A page this firmware lacks answers with an error: only that page's fields stay None
        try:
            return self.request('admin/{}&operation={}'.format(form, operation), 'operation={}'.format(operation))
        except ClientError:
            return None

    def get_security_settings(self) -> SecuritySettings:
        # Read only: remote management, DMZ, UPnP, port forwards, firewall and access control (Security, NAT and
        # Administration pages). Counts only, no client names, MACs or the WAN address
        remote = self._security_read('administration?form=remote')
        dmz = self._security_read('nat?form=dmz')
        forwards = _security_rows(self._security_read('nat?form=vs'))
        mappings = _security_rows(self._security_read('upnp?form=service'))
        firewall = self._security_read('security_settings?form=new_enable')
        mode = self._security_read('access_control?form=mode')
        settings = SecuritySettings(
            remote_management=_security_flag(remote, 'enable'),
            local_https=_security_flag(self._security_read('administration?form=https'), 'https_enable'),
            dmz=_security_flag(dmz, 'enable'),
            upnp=_security_flag(self._security_read('upnp?form=enable'), 'enable'),
            spi_firewall=_security_flag(firewall, 'enable'),
            ping_from_wan=_security_flag(firewall, 'wan_ping'),
            ping_from_lan=_security_flag(firewall, 'lan_ping'),
            access_control=_security_flag(self._security_read('access_control?form=enable'), 'enable'),
        )
        if isinstance(remote, dict):
            settings.remote_management_any_address = {'all': True, 'specified': False}.get(remote.get('managers'))
            settings.remote_management_http_port = _security_int(remote.get('http_port'))
            settings.remote_management_https_port = _security_int(remote.get('https_port'))
        if settings.dmz:
            settings.dmz_host = dmz.get('ipaddr') or None
        if mappings is not None:
            settings.upnp_mappings = len(mappings)
            settings.upnp_mappings_by_protocol = dict(Counter(
                str(row['protocol']).upper() for row in mappings if row.get('protocol')))
        if forwards is not None:
            settings.port_forwards = len(forwards)
            settings.port_forwards_enabled = sum(1 for row in forwards if _security_flag(row, 'enable'))
        if isinstance(mode, dict):
            settings.access_control_mode = {'black': 'blacklist', 'white': 'whitelist'}.get(mode.get('access_mode'))
        if settings.access_control_mode == 'blacklist':
            blocked = _security_rows(self._security_read('access_control?form=black_list', 'load'))
            settings.access_control_blocked = None if blocked is None else len(blocked)
        return settings

    def get_homecare_status(self) -> HomeCareStatus:
        # HomeCare antivirus (Security > Antivirus)
        info = self._security_read('security?form=info')
        info = info if isinstance(info, dict) else {}
        rule = self._security_read('security?form=rule')
        updating = info.get('is_updating')
        return HomeCareStatus(
            malicious_content_filter=_security_flag(info, 'malicious_sites_blocking'),
            intrusion_prevention=_security_flag(info, 'intrusion_prevention_system'),
            infected_device_quarantine=_security_flag(info, 'infected_device_prevention_blocking'),
            protected_days=_security_int(info.get('protected_days')),
            database_checked=_security_time(info.get('checked_time')),
            database_updating=updating if isinstance(updating, bool) else None,
            rules_version=_security_int(rule.get('version')) if isinstance(rule, dict) else None,
        )

    def get_blocked_threats(self) -> BlockedThreats:
        # HomeCare history of blocked threats. Each entry also names the client, its owner and the site,
        # attacker or blocked IP: only counts, kinds and the newest time are kept
        rows = _security_rows(self.request('admin/security?form=history&operation=read', 'operation=read')) or []
        newest = max(rows, key=lambda row: _security_int(row.get('timestamp')) or 0, default={})
        return BlockedThreats(
            events=len(rows),
            hits=sum(_security_int(row.get('hits')) or 0 for row in rows),
            by_type=dict(Counter(str(row['type']) for row in rows if row.get('type'))),
            last_time=_security_time(newest.get('timestamp')),
            last_type=str(newest['type']) if newest.get('type') else None,
            last_category_id=_security_int(newest.get('category_id')),
        )

    def get_ip_mac_binding(self) -> IpMacBinding:
        # IP & MAC Binding (Security page): whether it is on and how many ARP entries and bindings there are
        arp = _security_rows(self._security_read('imb?form=arp_list', 'load'))
        bindings = _security_rows(self._security_read('imb?form=bind_list', 'load'))
        return IpMacBinding(
            enable=_security_flag(self._security_read('imb?form=setting'), 'enable'),
            arp_entries=None if arp is None else len(arp),
            bindings=None if bindings is None else len(bindings),
        )

    def get_firmware_update(self) -> FirmwareUpdate:
        # Read only. The installed version, then what the web UI shows about TP-Link's cloud: the update count of
        # its top bar (check_upgrade) and the newest version on the Firmware Upgrade page (cloud_upgrade, load).
        # operation=upgrade on that same cloud_upgrade form starts the online upgrade: it is never sent here
        data = self.request('admin/firmware?form=upgrade&operation=read', 'operation=read')
        update = FirmwareUpdate(installed_version=data.get('firmware_version') or None)
        check = self._read_or_empty('admin/cloud_account?form=check_upgrade', 'read')
        cloud = self._read_or_empty('admin/cloud_account?form=cloud_upgrade', 'load')

        update.latest_version = cloud.get('latest_version') or None
        if cloud.get('detail'):
            update.release_notes = (cloud['detail'].replace('\\n', '\n').replace('\\t', '\t')
                                    .replace("\\'", "'").strip() or None)
        answers = []
        try:
            answers.append(int(check['update_number']) > 0)
        except (KeyError, TypeError, ValueError):
            pass
        # latest_flag: the installed firmware is already the newest one
        latest_flag = {True: True, False: False, 'true': True, 'false': False}.get(cloud.get('latest_flag'))
        if latest_flag is True or (update.latest_version and update.latest_version == update.installed_version):
            answers.append(False)
        elif latest_flag is False and update.latest_version:
            answers.append(True)
        update.update_available = any(answers) if answers else None
        return update

    def _read_or_empty(self, path: str, operation: str) -> dict:
        # Answers that depend on TP-Link's cloud fail without internet or a TP-Link ID: {} instead of an error
        try:
            data = self.request('{}&operation={}'.format(path, operation), 'operation={}'.format(operation))
        except ClientError:
            return {}
        return data if isinstance(data, dict) else {}

    def get_reboot_schedule(self) -> RebootSchedule:
        data = self.request('admin/reboot?form=set&operation=read', 'operation=read')
        return RebootSchedule(
            enable={'on': True, 'off': False}.get(data.get('enable')),
            time=data.get('time') or None,
            cycle=data.get('cycle') or None,
            day=data.get('day') or None,
        )

    def set_reboot_schedule(self, enable: bool, time: str = None, cycle: str = None, day: str = None) -> None:
        # The web page sends the whole form: what is not given keeps its current value
        data = self.request('admin/reboot?form=set&operation=read', 'operation=read')
        values = {'operation': 'write', 'enable': 'on' if enable else 'off'}
        for key, value in (('time', time), ('cycle', cycle), ('day', day)):
            value = data.get(key) if value is None else value
            if value is not None:
                values[key] = value
        self.request('admin/reboot?form=set', urlencode(values))

    def get_router_time(self) -> RouterTime:
        data = self.request('admin/time?form=settings&operation=read', 'operation=read')
        dst = self.request('admin/time?form=dst&operation=read', 'operation=read')
        read_at = datetime.now(timezone.utc)
        clock = None
        if data.get('date') and data.get('time'):
            # BR_FORMAT dates are DD/MM/YYYY; the default (UN_FORMAT) is MM/DD/YYYY
            date_format = '%d/%m/%Y' if str(data.get('time_format')).upper() == 'BR_FORMAT' else '%m/%d/%Y'
            try:
                clock = datetime.strptime('{} {}'.format(data['date'], data['time']), date_format + ' %H:%M:%S')
            except ValueError:
                pass

        def dst_rule(edge: str) -> str | None:
            parts = [dst.get('{}_{}'.format(edge, key)) for key in ('week', 'day', 'month', 'hour')]
            return ' '.join(parts) if all(parts) else None

        return RouterTime(
            time=clock,
            read_at=read_at if clock else None,
            # auto = from the NTP servers; pc / manual = set from a browser or by hand
            automatic=data['type'] == 'auto' if data.get('type') else None,
            timezone=data.get('timezone') or None,
            ntp_servers=[data[key] for key in ('ntp_svr1', 'ntp_svr2') if data.get(key)],
            dst_enable={'on': True, 'off': False}.get(dst.get('dst_enable')),
            dst_active={'up': True, 'down': False}.get(dst.get('dst_status')),
            dst_start=dst_rule('start'),
            dst_end=dst_rule('end'),
        )

    def get_system_log(self) -> SystemLog:
        # Only how many entries there are, per level: the entries themselves name clients (MAC, IP). The list
        # follows the type / level filter chosen on the System Log page
        rows = self.request('admin/syslog?form=log&operation=load', 'operation=load')
        if not isinstance(rows, list):
            return SystemLog()
        levels = {}
        for row in rows:
            level = str(row.get('level') or 'unknown').lower()
            levels[level] = levels.get(level, 0) + 1
        return SystemLog(entries=len(rows), levels=levels)

    def traffic_monitor_status(self) -> bool | None:
        data = self.request('admin/traffic?form=status&operation=read', 'operation=read')
        return {'on': True, 'off': False}.get(data.get('enable'))

    def set_traffic_monitor(self, enable: bool) -> None:
        # What the switch on the Traffic Monitor page sends (no Save button)
        self.request('admin/traffic?form=status', 'operation=write&enable={}'.format('on' if enable else 'off'))

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

    # Every WiFi network by its form name: main and guest, 2.4 GHz and both 5 GHz bands (tri-band)
    WIFI_NETWORK_FORMS = ('wireless_2g', 'wireless_5g', 'wireless_5g_2', 'guest_2g', 'guest_5g', 'guest_5g_2')

    def get_wifi_networks(self) -> dict[str, WifiNetwork]:
        # One read per network. A network the router does not have (the second 5 GHz band on a dual-band model)
        # is left out. Never the password: psk_key, wpa_key and wep_key* are not copied
        networks = {}
        error = None
        for form in self.WIFI_NETWORK_FORMS:
            try:
                data = self.request('admin/wireless?form={}&operation=read'.format(form), 'operation=read')
            except ClientException as e:
                error = e
                continue
            if isinstance(data, dict):
                networks[form] = self._wifi_network(form, data)
        if not networks and error is not None:
            raise error
        return networks

    @staticmethod
    def _wifi_network(form: str, data: dict) -> WifiNetwork:
        # A single-form read has unprefixed keys (ssid); a multi-form one, prefixed keys (wireless_2g_ssid)
        def get(key):
            value = data.get('{}_{}'.format(form, key), data.get(key))
            return None if value == '' else value

        current = get('current_channel')
        return WifiNetwork(
            enable=_flag(get('enable')),
            ssid=get('ssid'),
            hidden=_flag(get('hidden')),
            encryption=get('encryption'),
            channel=None if get('channel') is None else str(get('channel')),
            current_channel=int(current) if str(current).isdigit() else None,
            hwmode=get('hwmode'),
            htmode=get('htmode'),
            txpower=get('txpower'),
            airtime_fairness=_flag(get('airtime_fairness')),
            mu_mimo=_flag(get('mu_mimo')),
        )

    def wifi_schedule_status(self) -> WifiSchedule:
        # Wireless Off Time Schedule: whether it is on, how many off periods it has and which bands it has off now
        data = self.request('admin/wireless?form=wireless_schedule&operation=read', 'operation=read')
        periods = data.get('list')
        schedule = WifiSchedule(
            enable=_flag(data.get('enable')),
            # The router sends {} when there is none; the web page reads a list of "days:[from,to]" strings
            off_periods=len(periods) if isinstance(periods, (list, dict)) else None,
            periods=_wifi_off_periods(periods),
        )
        try:
            now = self.request('admin/wireless?form=wireless_schedule_wifi_disable&operation=read', 'operation=read')
        except ClientException:
            return schedule
        schedule.off_now_2g = _flag(now.get('disable_2g'))
        schedule.off_now_5g = _flag(now.get('disable_5g'))
        schedule.off_now_5g_2 = _flag(now.get('disable_52g'))
        return schedule

    def set_wifi_schedule(self, enable: bool) -> None:
        # What the switch of the Wireless Schedule page sends; the off periods (list) stay as they are
        self.request('admin/wireless?form=wireless_schedule',
                     'operation=write&enable={}'.format('on' if enable else 'off'))

    def set_wifi_off_periods(self, periods: list[WifiOffPeriod]) -> None:
        # Like the Wireless Schedule page: the whole list, as JSON, of "days:[from,to]" ("eve" = every day, else
        # day names joined by commas), whole hours 0-24. The schedule's on/off switch is not touched
        entries = []
        for period in periods:
            if not all(isinstance(hour, int) and 0 <= hour <= 24 for hour in (period.start, period.end)):
                raise ValueError('WiFi off hours must be whole hours from 0 to 24')
            unknown = set(period.days) - set(WIFI_DAYS)
            if unknown:
                raise ValueError('Unknown days: {}'.format(sorted(unknown)))
            days = ','.join(day for day in WIFI_DAYS if day in period.days) if period.days else 'eve'
            entries.append('{}:[{},{}]'.format(days, period.start, period.end))
        self.request('admin/wireless?form=wireless_schedule',
                     urlencode({'operation': 'write', 'list': dumps(entries, separators=(',', ':'))}))

    def set_wifi_off_period(self, start: int = None, end: int = None, days: list[str] = None) -> None:
        # Change the first off period, keeping the others; with none yet, start one (23 -> 7, every day)
        periods = self.wifi_schedule_status().periods or []
        first = periods[0] if periods else WifiOffPeriod(start=23, end=7, days=[])
        changed = WifiOffPeriod(start=first.start if start is None else start,
                                end=first.end if end is None else end,
                                days=first.days if days is None else list(days))
        self.set_wifi_off_periods([changed] + periods[1:])

    def remove_wifi_off_period(self) -> None:
        # Remove the first off period, keeping the others
        periods = self.wifi_schedule_status().periods or []
        if periods:
            self.set_wifi_off_periods(periods[1:])

    def wps_status(self) -> bool | None:
        # WPS switch of System Parameters
        data = self.request('admin/wireless?form=syspara_wps&operation=read', 'operation=read')
        return _flag(data.get('wps'))

    def guest_network_access(self) -> GuestNetworkAccess:
        # Guest Network settings shared by every band. In the web page, isolate is the box "Allow guests to access
        # each other" and access is "Allow guests to access my local network" (on = allowed)
        data = self.request('admin/wireless?form=guest&operation=read', 'operation=read')
        return GuestNetworkAccess(each_other=_flag(data.get('isolate')), local_network=_flag(data.get('access')))

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

    def get_usb_storage(self) -> UsbStorage:
        # USB disks (USB Settings > Sharing Access). With no disk the list is an empty object. The size of each disk
        # comes from its volumes (contents&serial=...), as the web page reads them: not checked with a disk yet
        data = self.request('admin/disk_setting?form=metadata&operation=read', 'operation=read')
        disks = data.get('list')
        disks = [disk for disk in disks if isinstance(disk, dict)] if isinstance(disks, list) else []
        try:
            count = int(data['number'])
        except (KeyError, TypeError, ValueError):
            count = len(disks) if 'list' in data else None
        storage = UsbStorage(disks=count)

        capacity = used = free = 0
        sized = False
        for disk in disks:
            if not disk.get('serial'):
                continue
            try:
                volumes = self.request('admin/disk_setting?form=contents&serial={}&operation=load'
                                       .format(quote(str(disk['serial']), safe='')), 'operation=load')
            except Exception:
                continue
            for volume in volumes if isinstance(volumes, list) else []:
                size, left = _usb_size(volume.get('capacity')), _usb_size(volume.get('free'))
                if size is None or left is None:
                    continue
                taken = _usb_size(volume.get('used'))
                capacity, free = capacity + size, free + left
                used += taken if taken is not None else max(size - left, 0)
                sized = True
        if sized:
            storage.capacity, storage.used, storage.free = capacity, used, free
        return storage

    def get_usb_sharing(self) -> UsbSharing:
        # Which USB services are on: Samba, FTP and FTP via internet (one row per protocol), Media Sharing and
        # Time Machine. Leaves out each row's internal key and the server name
        rows = self.request('admin/folder_sharing?form=settings&operation=read', 'operation=read')
        media = self.request('admin/folder_sharing?form=media&operation=read', 'operation=read')
        time_machine = self.request('admin/time_machine?form=settings&operation=read', 'operation=read')
        on_off = {'on': True, 'off': False}
        enabled = {str(row.get('protocol')).lower(): on_off.get(row.get('enable'))
                   for row in (rows if isinstance(rows, list) else []) if isinstance(row, dict)}
        return UsbSharing(
            samba=enabled.get('samba'),
            ftp=enabled.get('ftp'),
            ftp_internet=enabled.get('ftpex'),
            media_sharing=on_off.get(media.get('media_sharing')) if isinstance(media, dict) else None,
            time_machine=on_off.get(time_machine.get('enable')) if isinstance(time_machine, dict) else None,
        )

    def print_server_status(self) -> bool | None:
        # Not checked on this firmware yet: the web page reads admin/print_server (no form) and shows enable,
        # name and printer_count
        data = self.request('admin/print_server', 'operation=read')
        return {'on': True, 'off': False}.get(data.get('enable')) if isinstance(data, dict) else None

    def get_vpn_server_settings(self) -> VpnServerSettings:
        # OpenVPN and PPTP server settings. Leaves out cert_exist, netbios_pass and the client address ranges
        openvpn = self.request('admin/openvpn?form=config&operation=read', 'operation=read')
        pptp = self.request('admin/pptpd?form=config&operation=read', 'operation=read')
        on_off = {'on': True, 'off': False}
        port = str(openvpn.get('port', ''))
        return VpnServerSettings(
            openvpn_enabled=on_off.get(openvpn.get('enabled')),
            openvpn_protocol=openvpn.get('proto') or None,
            openvpn_port=int(port) if port.isdigit() else None,
            openvpn_access=openvpn.get('access') or None,
            pptp_enabled=on_off.get(pptp.get('enabled')),
            pptp_unencrypted_access=on_off.get(pptp.get('unencrypted_access')),
            pptp_samba_access=on_off.get(pptp.get('samba_access')),
        )


def _usb_size(value) -> int | None:
    # Disk sizes come as text like "16GB" or "14.8G"; the web page counts K, M, G, T as powers of 1000
    match = search(r'^\s*(\d+(?:\.\d+)?)\s*([KMGTP])', str(value), IGNORECASE) if value is not None else None
    if not match:
        return None
    return int(float(match.group(1)) * 1000 ** ('KMGTP'.index(match.group(2).upper()) + 1))
