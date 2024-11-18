from datetime import timedelta
from ipaddress import IPv4Address
from logging import Logger
from urllib.parse import unquote

from macaddress import EUI48
from requests import Session

from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.dataclass import (Device, Firmware, IPv4DHCPLease,
                                              IPv4Reservation, IPv4Status,
                                              Status)
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection


class TPLinkXDRClient(AbstractRouter):
    _stok = ''

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._session = Session()

    def supports(self) -> bool:
        response = self._session.get(self.host, timeout=self.timeout, verify=self._verify_ssl)
        return response.text.index('TL-XDR') >= 0

    def authorize(self) -> None:
        response = self._session.post(self.host, json={
            'method': 'do',
            'login': {
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

    def logout(self) -> None:
        data = self._request({
            'method': 'do',
            'system': {
                'logout': None,
            },
        })
        if data['error_code'] != 0:
            raise ClientException('TplinkRouter - {} - logout failed, code - {}'.
                                  format(self.__class__, data['error_code']))
        self._stok = ''

    def get_firmware(self) -> Firmware:
        data = self._request({
            'method': 'get',
            'device_info': {
                'name': 'info',
            },
        })
        dev_info = data['device_info']['info']
        return Firmware(dev_info['hw_version'], dev_info['device_model'], dev_info['sw_version'])

    def get_status(self) -> Status:
        data = self._request({
            'method': 'get',
            'hosts_info': {
                'table': 'host_info',
            },
            'network': {
                'name': [
                    'wan_status',
                    'lan',
                ],
            },
            'wireless': {
                'name': [
                    'wlan_bs',
                    'wlan_host_2g',
                    'wlan_wds_2g',
                    'wlan_host_5g',
                    'wlan_wds_5g',
                ]
            },
            'guest_network': {
                'name': [
                    'guest_2g',
                ]
            }
        })

        status = Status()
        status._wan_ipv4_addr = get_ip(data['network']['wan_status']['ipaddr'])
        status._lan_ipv4_addr = get_ip(data['network']['lan']['ipaddr'])
        status._lan_macaddr = get_mac(data['network']['lan']['macaddr'])
        status.wifi_2g_enable = data['wireless']['wlan_host_2g']['enable'] == '1'
        status.wifi_5g_enable = (data['wireless']['wlan_host_5g']['enable'] == '1' or
                                 data['wireless']['wlan_bs']['bs_enable'] == '1')
        status.guest_2g_enable = data['guest_network']['guest_2g']['enable'] == '1'

        for item_map in data['hosts_info']['host_info']:
            item = item_map[next(iter(item_map))]
            conn_type = Connection.UNKNOWN
            if item['type'] == '0':
                conn_type = Connection.WIRED
            elif item['type'] == '1' and item['wifi_mode'] == '0':
                conn_type = Connection.HOST_2G
            elif item['type'] == '1' and item['wifi_mode'] == '1':
                conn_type = Connection.HOST_5G

            dev = Device(conn_type, get_mac(item['mac']), get_ip(item['ip']), unquote(item['hostname']))
            dev.up_speed = item['up_speed']
            dev.down_speed = item['down_speed']
            status.devices.append(dev)
        return status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        data = self._request({
            'method': 'get',
            'ip_mac_bind': {
                'table': 'user_bind',
            },
        })

        ipv4_reservations = []
        for item_map in data['ip_mac_bind']['user_bind']:
            item = item_map[next(iter(item_map))]
            ipv4_reservations.append(IPv4Reservation(
                EUI48(item['mac']),
                IPv4Address(item['ip']),
                item['hostname'],
                True,
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
                get_mac(item['mac']),
                get_ip(item['ip']),
                item['hostname'],
                str(timedelta(seconds=int(item['expires']))) if item['expires'] != '4294967295' else 'Permanent',
            ))
        return dhcp_leases

    def get_ipv4_status(self) -> IPv4Status:
        data = self._request({
            'method': 'get',
            'dhcpd': {
                'name': 'udhcpd',
            },
            'network': {
                'name': [
                    'lan',
                    'wan_status',
                ],
            },
        })

        ipv4_status = IPv4Status()
        ipv4_status._wan_ipv4_ipaddr = get_ip(data['network']['wan_status']['ipaddr'])
        ipv4_status._wan_ipv4_gateway = get_ip(data['network']['wan_status']['gateway'])
        ipv4_status._wan_ipv4_netmask = get_ip(data['network']['wan_status']['netmask'])
        ipv4_status._wan_ipv4_pridns = get_ip(data['network']['wan_status']['pri_dns'])
        ipv4_status._wan_ipv4_snddns = get_ip(data['network']['wan_status']['snd_dns'])
        ipv4_status._lan_macaddr = get_mac(data['network']['lan']['macaddr'])
        ipv4_status._lan_ipv4_ipaddr = get_ip(data['network']['lan']['ipaddr'])
        ipv4_status.lan_ipv4_dhcp_enable = data['dhcpd']['udhcpd']['enable'] == '1'
        ipv4_status._lan_ipv4_netmask = get_ip(data['network']['lan']['netmask'])
        return ipv4_status

    def reboot(self) -> None:
        data = self._request({
            'method': 'do',
            'system': {
                'reboot': None,
            },
        })
        self._stok = ''
        if data['error_code'] != 0:
            raise ClientException('TplinkRouter - {} - reboot failed, code - {}'.
                                  format(self.__class__, data['error_code']))

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        payload_map = {
            Connection.HOST_2G: {
                'method': 'set',
                'wireless': {
                    'wlan_host_2g': {
                        'enable': 1 if enable else 0,
                    },
                },
            },
            Connection.HOST_5G: {
                'method': 'set',
                'wireless': {
                    'wlan_host_5g': {
                        'enable': 1 if enable else 0,
                    },
                },
            },
            Connection.GUEST_2G: {
                'method': 'set',
                'guest_network': {
                    'guest_2g': {
                        'enable': '1' if enable else '0',
                    },
                },
            },
        }
        if wifi not in payload_map:
            raise ClientException('Not supported')
        payload = payload_map[wifi]
        data = self._request(payload)
        if data['error_code'] != 0:
            raise ClientException('TplinkRouter - {} - set wifi failed, code - {}'.
                                  format(self.__class__, data['error_code']))

    def _request(self, payload: dict) -> dict:
        url = '{}/stok={}/ds'.format(self.host, self._stok)
        response = self._session.post(url, json=payload, timeout=self.timeout, verify=self._verify_ssl)
        return response.json()

    @staticmethod
    def _encode_password(pwd: str) -> str:
        return TPLinkXDRClient._security_encode(
            pwd,
            'RDpbLfCPsJZ7fiv',
            ('yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD'
                '02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLg'
                'MLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ'
                '1xtXcPcf1aT303wAQhv66qzW'),
        )

    @staticmethod
    def _security_encode(data1: str, data2: str, char_dict: str) -> str:
        data1_len = len(data1)
        data2_len = len(data2)
        dict_len = len(char_dict)
        res = ''
        for c in range(max(data1_len, data2_len)):
            a = b = 187
            if c >= data1_len:
                a = ord(data2[c])
            elif c >= data2_len:
                b = ord(data1[c])
            else:
                b = ord(data1[c])
                a = ord(data2[c])
            res += char_dict[(b ^ a) % dict_len]
        return res
