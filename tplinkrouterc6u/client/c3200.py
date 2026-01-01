import base64
import re
from datetime import timedelta
from ipaddress import IPv4Address
from re import search
from time import sleep
from urllib.parse import urlparse

import requests
from macaddress import EUI48
from requests import Response

from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.dataclass import (
    Firmware,
    Status,
    Device,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.common.helper import get_ip, get_mac, get_value
from tplinkrouterc6u.common.package_enum import Connection


class TplinkC3200Router(AbstractRouter):
    # Variable de session vers le routeur
    # Cette session va contenir tout ce qu'il faut une fois connecté, en particulier :
    #  - Le Referer qui permet d'être accepté dans le CGI
    #  - Le coookie d'authentification
    SESSION: requests.Session

    # Nombre de Retry possibles
    REQUEST_RETRIES = 1

    CLIENT_TYPES = {
        0: Connection.WIRED,
        1: Connection.HOST_2G,
        3: Connection.HOST_5G,
        2: Connection.GUEST_2G,
        4: Connection.GUEST_5G,
    }

    ''' ___________________________________________________
        Méthodes de connection 
        ___________________________________________________ '''

    def supports(self) -> bool:
        # Cette méthode est utilisée pour voir si le serveur spécifié par l'URL est bien supporté par cette classe
        # Téléchargement et recherche du modèle .
        page_accueil = requests.get(self.host, timeout=5)
        if not page_accueil or page_accueil.status_code != 200:
            return False

        if re.search("Archer", page_accueil.text):
            return True

        return False

    def authorize(self) -> None:

        # ———————————————————————————————————————————
        # Création de la session + cookie
        # ———————————————————————————————————————————
        self.SESSION = requests.Session()

        if self._logger:
            self._logger.debug("Dans C3200!")
        # Domaine nécessaire pour le cookie → extrait à partir de l’URL
        router_host = urlparse(self.host).hostname
        if not router_host:
            raise ValueError(self.host & " doit contenir un host valide, ex. http://192.168.168.1")

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
        response: Response

        try:
            response = self.SESSION.post(login_url, timeout=10)
        except Exception as e:
            error = "TplinkRouter - C3200 - Cannot authorize! Error - {}; Response - {}".format(e, response.text)
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def logout(self) -> None:
        self.SESSION.cookies.clear(domain=urlparse(self.host).hostname, path="/")

    class ActItem:
        GET = 1
        SET = 2
        ADD = 3
        DEL = 4
        GL = 5
        GS = 6
        OP = 7
        CGI = 8

        def __init__(self, type: int, oid: str, stack: str = '0,0,0,0,0,0', pstack: str = '0,0,0,0,0,0',
                     attrs: list = []):
            self.type = type
            self.oid = oid
            self.stack = stack
            self.pstack = pstack
            self.attrs = attrs

    def req_act(self, acts: list):
        '''
        Requests ACTs via the cgi proxy
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

        data = '&'.join(act_types) + '\r\n' + ''.join(act_data)

        url = f"{self.host}/cgi?" + '&'.join(act_types)
        (code, response) = self._request(url, data_str=''.join(act_data))

        if code != 200:
            error = 'TplinkRouter - C3200 -  Response with error; Request {} - Response {}'.format(data, response)
            if self._logger:
                self._logger.debug(error)
            raise ClientError(error)

        result = self._merge_response(response)

        return response, result.get('0') if len(result) == 1 and result.get('0') else result

    def _request(self, url, method='POST', data_str=None):

        retry = 0
        while retry < self.REQUEST_RETRIES:
            # send the request
            if method == 'POST':
                r = self.SESSION.post(url, data=data_str)
            elif method == 'GET':
                r = self.session.get(url, data=data_str)
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

    # Cette méthode prend en entrée la réponse du CGI serveur du routeur et donne en sortie une structure de données générique
    @staticmethod
    def _merge_response(response: str) -> dict:
        result = {}
        obj = {}
        lines = response.split('\n')
        for line in lines:
            if line.startswith('['):
                regexp = search(r'\[\d+,\d+,\d+,\d+,\d+,\d+\](\d+)', line)
                if regexp is not None:
                    obj = {}
                    index = regexp.group(1)
                    item = result.get(index)
                    if item is not None:
                        if item.__class__ != list:
                            result[index] = [item]
                        result[index].append(obj)
                    else:
                        result[index] = obj
                continue
            if '=' in line:
                keyval = line.split('=')
                assert len(keyval) == 2

                obj[keyval[0]] = keyval[1]

        return result if result else []

    # Méthode utilitaire pour avoir une liste à chaque fois, y compris vide
    @staticmethod
    def _to_list(response: dict | list | None) -> list:
        if response is None:
            return []

        return [response] if response.__class__ != list else response

    ''' ___________________________________________________
    Méthodes implémentant les interfaces
    ___________________________________________________ '''

    def get_firmware(self) -> Firmware:
        acts = [
            self.ActItem(self.ActItem.GET, 'IGD_DEV_INFO', attrs=['hardwareVersion', 'softwareVersion', 'modelName']),
        ]
        _, values = self.req_act(acts)

        return Firmware(values['hardwareVersion'], values['modelName'], values['softwareVersion'])

    def get_status(self) -> Status:
        status = Status()
        acts = [
            self.ActItem(self.ActItem.GS, 'LAN_IP_INTF', attrs=['X_TP_MACAddress', 'IPInterfaceIPAddress']),
            self.ActItem(self.ActItem.GS, 'WAN_IP_CONN',
                         attrs=['enable', 'MACAddress', 'externalIPAddress', 'defaultGateway', 'name']),
            self.ActItem(self.ActItem.GL, 'LAN_WLAN', attrs=['enable', 'X_TP_Band']),
            self.ActItem(self.ActItem.GL, 'LAN_WLAN_GUESTNET', attrs=['enable', 'name']),
            self.ActItem(self.ActItem.GL, 'LAN_HOST_ENTRY', attrs=[
                'IPAddress',
                'MACAddress',
                'hostName',
                'X_TP_ConnType',
                'active',
            ]),
            self.ActItem(self.ActItem.GS, 'LAN_WLAN_ASSOC_DEV', attrs=[
                'associatedDeviceMACAddress',
                'X_TP_TotalPacketsSent',
                'X_TP_TotalPacketsReceived',
            ]),
        ]
        _, values = self.req_act(acts)

        if values['0'].__class__ == list:
            values['0'] = values['0'][0]

        status._lan_macaddr = EUI48(values['0']['X_TP_MACAddress'])
        status._lan_ipv4_addr = IPv4Address(values['0']['IPInterfaceIPAddress'])

        for item in self._to_list(values.get('1')):
            if int(item['enable']) == 0 and values.get('1').__class__ == list:
                continue
            status._wan_macaddr = EUI48(item['MACAddress']) if item.get('MACAddress') else None
            status._wan_ipv4_addr = IPv4Address(item['externalIPAddress'])
            status._wan_ipv4_gateway = IPv4Address(item['defaultGateway'])
            status.conn_type = item.get('name', '')

        if values['2'].__class__ != list:
            status.wifi_2g_enable = bool(int(values['2']['enable']))
        else:
            status.wifi_2g_enable = bool(int(values['2'][0]['enable']))
            status.wifi_5g_enable = bool(int(values['2'][1]['enable']))

        if values['3'].__class__ != list:
            status.guest_2g_enable = bool(int(values['3']['enable']))
        else:
            status.guest_2g_enable = bool(int(values['3'][0]['enable']))
            status.guest_5g_enable = bool(int(values['3'][1]['enable']))

        devices = {}
        for val in self._to_list(values.get('4')):
            if int(val['active']) == 0:
                continue
            conn = self.CLIENT_TYPES.get(int(val['X_TP_ConnType']))
            if conn is None:
                continue
            elif conn == Connection.WIRED:
                status.wired_total += 1
            elif conn.is_guest_wifi():
                status.guest_clients_total += 1
            elif conn.is_host_wifi():
                status.wifi_clients_total += 1
            devices[val['MACAddress']] = Device(conn,
                                                EUI48(val['MACAddress']),
                                                IPv4Address(val['IPAddress']),
                                                val['hostName'])

        for val in self._to_list(values.get('5')):
            if val['associatedDeviceMACAddress'] not in devices:
                status.wifi_clients_total += 1
                devices[val['associatedDeviceMACAddress']] = Device(
                    Connection.HOST_2G,
                    EUI48(val['associatedDeviceMACAddress']),
                    IPv4Address('0.0.0.0'),
                    '')
            devices[val['associatedDeviceMACAddress']].packets_sent = int(val['X_TP_TotalPacketsSent'])
            devices[val['associatedDeviceMACAddress']].packets_received = int(val['X_TP_TotalPacketsReceived'])

        status.devices = list(devices.values())
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        acts = [
            self.ActItem(self.ActItem.GL, 'LAN_DHCP_STATIC_ADDR', attrs=['enable', 'chaddr', 'yiaddr', 'description']),
        ]
        _, values = self.req_act(acts)

        ipv4_reservations = []
        for item in self._to_list(values):
            ipv4_reservations.append(
                IPv4Reservation(
                    EUI48(item['chaddr']),
                    IPv4Address(item['yiaddr']),
                    item['description'],
                    bool(int(item['enable']))
                ))

        return ipv4_reservations

    def get_ipv4_dhcp_leases(self) -> [IPv4DHCPLease]:
        acts = [
            self.ActItem(self.ActItem.GL, 'LAN_HOST_ENTRY', attrs=['IPAddress', 'MACAddress', 'hostName',
                                                                   'leaseTimeRemaining']),
        ]
        _, values = self.req_act(acts)

        dhcp_leases = []
        for item in self._to_list(values):
            lease_time = item['leaseTimeRemaining']
            dhcp_leases.append(
                IPv4DHCPLease(
                    EUI48(item['MACAddress']),
                    IPv4Address(item['IPAddress']),
                    item['hostName'],
                    str(timedelta(seconds=int(lease_time))) if lease_time.isdigit() else 'Permanent',
                ))

        return dhcp_leases

    def get_ipv4_status(self) -> IPv4Status:
        acts = [
            self.ActItem(self.ActItem.GS, 'LAN_IP_INTF',
                         attrs=['X_TP_MACAddress', 'IPInterfaceIPAddress', 'IPInterfaceSubnetMask']),
            self.ActItem(self.ActItem.GET, 'LAN_HOST_CFG', '1,0,0,0,0,0', attrs=['DHCPServerEnable']),
            self.ActItem(self.ActItem.GS, 'WAN_IP_CONN',
                         attrs=['enable', 'MACAddress', 'externalIPAddress', 'defaultGateway', 'name', 'subnetMask',
                                'DNSServers']),
        ]
        _, values = self.req_act(acts)

        ipv4_status = IPv4Status()
        ipv4_status._lan_macaddr = get_mac(get_value(values, ['0', 'X_TP_MACAddress'], '00:00:00:00:00:00'))
        ipv4_status._lan_ipv4_ipaddr = get_ip(get_value(values, ['0', 'IPInterfaceIPAddress'], '0.0.0.0'))
        ipv4_status._lan_ipv4_netmask = get_ip(get_value(values, ['0', 'IPInterfaceSubnetMask'], '0.0.0.0'))
        ipv4_status.lan_ipv4_dhcp_enable = bool(int(get_value(values, ['1', 'DHCPServerEnable'], '0')))

        for item in self._to_list(values.get('2')):
            if int(item.get('enable', '0')) == 0 and values.get('2').__class__ == list:
                continue
            ipv4_status._wan_macaddr = get_mac(item.get('MACAddress', '00:00:00:00:00:00'))
            ipv4_status._wan_ipv4_ipaddr = get_ip(item.get('externalIPAddress', '0.0.0.0'))
            ipv4_status._wan_ipv4_gateway = get_ip(item.get('defaultGateway', '0.0.0.0'))
            ipv4_status._wan_ipv4_conntype = item.get('name', '')
            ipv4_status._wan_ipv4_netmask = get_ip(item.get('subnetMask', '0.0.0.0'))
            dns = item.get('DNSServers', '').split(',')
            ipv4_status._wan_ipv4_pridns = get_ip(dns[0] if len(dns) > 0 else '0.0.0.0')
            ipv4_status._wan_ipv4_snddns = get_ip(dns[1] if len(dns) > 1 else '0.0.0.0')

        return ipv4_status

    def set_wifi(self, wifi: Connection, enable: bool) -> None:

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
                # on active les deux bandes de fréquence en même temps
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
        ''''CGI 7 et [ACT_REBOOT#0,0,0,0,0,0#0,0,0,0,0,0]0,0 '''

        acts = [
            self.ActItem(self.ActItem.OP, 'ACT_REBOOT'),
        ]
        _, values = self.req_act(acts)

        # print(values.keys())
