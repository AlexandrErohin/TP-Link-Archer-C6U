import math
from datetime import timedelta
from ipaddress import IPv4Address
from urllib.parse import unquote

from macaddress import EUI48

from tplinkrouterc6u.client.xdr import TPLinkXDRClient
from tplinkrouterc6u.common.dataclass import (Device, IPv4DHCPLease,
                                              IPv4Reservation,
                                              Status)
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


class TPLinkRClient(TPLinkXDRClient):
    _serv_id_map = {
        Connection.HOST_2G: '',
        Connection.HOST_5G: '',
        Connection.GUEST_2G: '',
        Connection.GUEST_5G: '',
    }

    def supports(self) -> bool:
        try:
            response = self._session.get('{}/login.htm'.format(self.host), timeout=self.timeout, verify=self._verify_ssl)
            return 'TL-R' in response.text
        except Exception:
            return False

    def authorize(self) -> None:
        response = self._session.post(self.host, json={
            'method': 'do',
            'login': {
                'username': self.username,
                'password': self._encode_password(self.password),
            }
        }, timeout=self.timeout, verify=self._verify_ssl)
        try:
            data = response.json()
            self._stok = data['stok']
        except Exception as e:
            error = ('TplinkRouter - {} - Cannot authorize! Error - {}; Response - {}'.
                     format(self.__class__.__name__, e, response))
            raise ClientException(error)

    def get_firmware(self) -> Firmware:
        data = self._request({
            'method': 'get',
            'device_info': {
                'name': 'info',
            },
        })
        dev_info = data['device_info']['info']
        hw_version = unquote(dev_info['hw_version'])
        device_model = unquote(dev_info['device_model'])
        sw_version = unquote(dev_info['sw_version'])
        return Firmware(hw_version, device_model, sw_version)

    def get_status(self) -> Status:
        data = self._request({
            'method': 'get',
            'host_management': {
                'table': ["host_info"],
            },
            'network': {
                'name': [
                    'wan_status',
                    'lan',
                ],
            },
            'apmng_wserv': {
                'table': ['wlan_serv'],
            }
        })

        status = Status()
        status._wan_ipv4_addr = get_ip(data['network']['wan_status']['ipaddr'])
        status._wan_ipv4_gateway = get_ip(data['network']['wan_status']['gateway'])
        status._lan_ipv4_addr = get_ip(data['network']['lan']['ipaddr'])
        status._lan_macaddr = get_mac(data['network']['lan']['macaddr'])

        for item_map in data['apmng_wserv']['wlan_serv']:
            item = item_map[next(iter(item_map))]
            bind_freq = self._bindFreq(item['default_bind_freq'])
            enable = item['enable'] == 'on'
            if item['network_type'] == '1' and bind_freq['2g']:
                status.wifi_2g_enable = enable
                self._serv_id_map[Connection.HOST_2G] = item['serv_id']
            elif item['network_type'] == '1' and bind_freq['5g']:
                status.wifi_5g_enable = enable
                self._serv_id_map[Connection.HOST_5G] = item['serv_id']
            elif item['network_type'] == '2' and bind_freq['2g']:
                status.guest_2g_enable = enable
                self._serv_id_map[Connection.GUEST_2G] = item['serv_id']
            elif item['network_type'] == '2' and bind_freq['5g']:
                status.guest_5g_enable = enable
                self._serv_id_map[Connection.GUEST_5G] = item['serv_id']

        for item_map in data['host_management']['host_info']:
            item = item_map[next(iter(item_map))]
            conn_type = Connection.UNKNOWN
            if item['type'] == 'wired':
                conn_type = Connection.WIRED
            elif item['type'] == 'wireless' and item['freq_name'] == '2.4GHz':
                conn_type = Connection.HOST_2G
            elif item['type'] == 'wireless' and item['freq_name'] == '5GHz':
                conn_type = Connection.HOST_5G

            dev = Device(conn_type, get_mac(item['mac']), get_ip(item['ip']), unquote(item['hostname']))
            if 'up_speed' in item:
                dev.up_speed = int(item['up_speed'])
            if 'down_speed' in item:
                dev.down_speed = int(item['down_speed'])
            if 'state' in item:
                dev.active = item['state'] == 'online'
            status.devices.append(dev)
        return status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        data = self._request({
            'method': 'get',
            'dhcpd': {
                'table': 'dhcp_static',
            },
        })

        ipv4_reservations = []
        for item_map in data['dhcpd']['dhcp_static']:
            item = item_map[next(iter(item_map))]
            ipv4_reservations.append(IPv4Reservation(
                EUI48(item['mac']),
                IPv4Address(item['ip']),
                item['note'],
                item['enable'] == 'on',
            ))
        return ipv4_reservations

    def get_ipv4_dhcp_leases(self) -> [IPv4DHCPLease]:
        data = self._request({
            'method': 'get',
            'dhcpd': {
                'table': 'dhcp_clients',
            },
        })

        dhcp_leases = []
        for item_map in data['dhcpd']['dhcp_clients']:
            item = item_map[next(iter(item_map))]
            dhcp_leases.append(IPv4DHCPLease(
                get_mac(item['macaddr']),
                get_ip(item['ipaddr']),
                item['hostname'],
                str(timedelta(seconds=int(item['expires']))) if item['expires'] != 'PERMANENT' else 'Permanent',
            ))
        return dhcp_leases

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        if wifi not in self._serv_id_map:
            raise ClientException('Not supported')
        if self._serv_id_map[wifi] == '':
            self.get_status()
            if self._serv_id_map[wifi] == '':
                raise ClientException('TplinkRouter - {} - set wifi failed, unable to get serv_id for {}'.
                        format(self.__class__), wifi)

        payload = {
            'method': 'set',
            'apmng_wserv': {
                'table': 'wlan_serv',
                'filter': [{'serv_id': self._serv_id_map[wifi]}],
                'para': {'enable': 'on' if enable else 'off'},
            },
        }

        data = self._request(payload)
        if data['error_code'] != 0:
            raise ClientException('TplinkRouter - {} - set wifi failed, code - {}'.
                                  format(self.__class__, data['error_code']))

    @staticmethod
    def _bindFreq(default_bind_freq: str) -> dict:
        bind_freq = int(default_bind_freq)
        result = {
            '2g': False,
            '5g': False,
        }

        if bind_freq % 2 == 1:  # 2.4G1
            result['2g'] = True
        elif math.floor(bind_freq / 2) % 2 == 1:  # 2.4G2
            result['2g'] = True
        elif math.floor(bind_freq / 256) % 2 == 1:  # 5G1
            result['5g'] = True
        elif math.floor(bind_freq / 512) % 2 == 1:  # 5G2
            result['5g'] = True
        elif bind_freq == 771:  # all
            result['2g'] = True
            result['5g'] = True

        return result
