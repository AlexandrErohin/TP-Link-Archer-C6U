from base64 import b64encode
from json import loads
from datetime import timedelta
from macaddress import EUI48
from ipaddress import IPv4Address
from logging import Logger
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device, IPv4Reservation, IPv4DHCPLease, IPv4Status
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.client.mr import TPLinkMRClientBase


class TPLinkEXClient(TPLinkMRClientBase):
    WIFI_SET = {
        Connection.HOST_2G: '1,0,0,0,0,0',
        Connection.HOST_5G: '2,0,0,0,0,0',
        Connection.GUEST_2G: '1,0,0,0,0,0',
        Connection.GUEST_5G: '2,0,0,0,0,0',
    }

    class ActItem:
        GET = 'go'
        GO = 'go'
        SET = 'so'
        ADD = 'add'
        DEL = 'del'
        GL = 'gl'
        GS = 'gs'
        OP = 'op'
        CGI = 'cgi'

        def __init__(self, type: str, oid: str, stack: str = '0,0,0,0,0,0', pstack: str = '0,0,0,0,0,0',
                     attrs: list = []):
            self.type = type
            self.oid = oid
            self.stack = stack
            self.pstack = pstack
            self.attrs = attrs

    def __init__(self, host: str, password: str, username: str = 'user', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self.username = 'user'
        self._url_rsa_key = 'cgi/getGDPRParm'

    def logout(self) -> None:
        '''
        Logs out from the host
        '''
        acts = [
            self.ActItem(self.ActItem.CGI, '/cgi/logout')
        ]

        response, _ = self.req_act(acts)

        if response == '':
            self._token = None

    def get_firmware(self) -> Firmware:
        acts = [
            self.ActItem(self.ActItem.GET, 'DEV2_DEV_INFO', attrs=[
                'hardwareVersion',
                'modelName',
                'softwareVersion'
            ])
        ]
        _, values = self.req_act(acts)

        if not values:
            raise ValueError('No firmware information received.')

        firmware = Firmware(
            values[0].get('hardwareVersion', ''),
            values[0].get('modelName', ''),
            values[0].get('softwareVersion', '')
        )

        return firmware

    def get_status(self) -> Status:
        status = Status()
        acts = [
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_LAN', attrs=['MACAddress', 'IPAddress']),
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_WAN',
                         attrs=['enable', 'MACAddr', 'connIPv4Address', 'connIPv4Gateway']),
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_WIFI_COMMON', attrs=['primaryEnable', 'guestEnable']),
            self.ActItem(self.ActItem.GL, 'DEV2_HOST_ENTRY',
                         attrs=['active', 'X_TP_LanConnType', 'physAddress', 'IPAddress', 'hostName']),
            self.ActItem(self.ActItem.GO, 'DEV2_MEM_STATUS', attrs=['total', 'free']),
            self.ActItem(self.ActItem.GO, 'DEV2_PROC_STATUS', attrs=['CPUUsage']),
        ]

        _, values = self.req_act(acts)

        if values[0].__class__ == list:
            values[0] = values[0][0]

        status._lan_macaddr = EUI48(values[0]['MACAddress'])
        status._lan_ipv4_addr = IPv4Address(values[0]['IPAddress'])

        for item in values[1]:
            if int(item['enable']) == 0 and values[1].__class__ == list:
                continue
            status._wan_macaddr = EUI48(item['MACAddr']) if item['MACAddr'] else None
            status._wan_ipv4_addr = IPv4Address(item['connIPv4Address'])
            status._wan_ipv4_gateway = IPv4Address(item['connIPv4Gateway'])

        if values[2].__class__ != list:
            status.wifi_2g_enable = bool(int(values[2]['primaryEnable']))
        else:
            status.wifi_2g_enable = bool(int(values[2][0]['primaryEnable']))
            status.wifi_5g_enable = bool(int(values[2][1]['primaryEnable']))

        if values[2].__class__ != list:
            status.guest_2g_enable = bool(int(values[2]['guestEnable']))
        else:
            status.guest_2g_enable = bool(int(values[2][0]['guestEnable']))
            status.guest_5g_enable = bool(int(values[2][1]['guestEnable']))

        devices = {}
        for val in self._to_list(values[3]):
            if int(val['active']) == 0:
                continue
            conn = self.CLIENT_TYPES.get(int(val['X_TP_LanConnType']))
            if conn is None:
                continue
            elif conn == Connection.WIRED:
                status.wired_total += 1
            elif conn.is_guest_wifi():
                status.guest_clients_total += 1
            elif conn.is_host_wifi():
                status.wifi_clients_total += 1
            devices[val['physAddress']] = Device(conn,
                                                 EUI48(val['physAddress']),
                                                 IPv4Address(val['IPAddress']),
                                                 val['hostName'])

        total = int(values[4]['total'])
        free = int(values[4]["free"])
        status.mem_usage = ((total - free) / total)

        status.cpu_usage = int(values[5]['CPUUsage']) / 100

        status.devices = list(devices.values())
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        acts = [
            self.ActItem(self.ActItem.GL, 'DEV2_DHCPV4_POOL_STATICADDR', attrs=['enable', 'chaddr', 'yiaddr']),
        ]
        _, values = self.req_act(acts)

        ipv4_reservations = []
        for item in values[0]:
            ipv4_reservations.append(
                IPv4Reservation(
                    EUI48(item['chaddr']),
                    IPv4Address(item['yiaddr']),
                    '',
                    bool(int(item['enable']))
                ))

        return ipv4_reservations

    def get_ipv4_dhcp_leases(self) -> [IPv4DHCPLease]:
        acts = [
            self.ActItem(self.ActItem.GL, 'DEV2_HOST_ENTRY',
                         attrs=['IPAddress', 'physAddress', 'hostName', 'leaseTimeRemaining']),
        ]
        _, values = self.req_act(acts)

        dhcp_leases = []
        for item in values[0]:
            lease_time = item['leaseTimeRemaining']
            dhcp_leases.append(
                IPv4DHCPLease(
                    EUI48(item['physAddress']),
                    IPv4Address(item['IPAddress']),
                    item['hostName'],
                    str(timedelta(seconds=int(lease_time))) if (lease_time.isdigit()
                                                                and int(lease_time)) > 0 else 'Permanent',
                ))

        return dhcp_leases

    def get_ipv4_status(self) -> IPv4Status:
        acts = [
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_LAN',
                         attrs=['MACAddress', 'IPAddress', 'IPSubnetMask', 'DHCPv4Enable']),
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_WAN',
                         attrs=['enable', 'MACAddr', 'connIPv4Address', 'connIPv4Gateway', 'name', 'connIPv4SubnetMask',
                                'connIPv4DnsServer']),
        ]
        _, values = self.req_act(acts)

        if values[0].__class__ == list:
            values[0] = values[0][0]

        ipv4_status = IPv4Status()
        ipv4_status._lan_macaddr = EUI48(values[0]['MACAddress'])
        ipv4_status._lan_ipv4_ipaddr = IPv4Address(values[0]['IPAddress'])
        ipv4_status._lan_ipv4_netmask = IPv4Address(values[0]['IPSubnetMask'])
        ipv4_status.lan_ipv4_dhcp_enable = bool(int(values[0]['DHCPv4Enable']))

        for item in values[1]:
            if int(item['enable']) == 0 and values[1].__class__ == list:
                continue
            ipv4_status._wan_macaddr = EUI48(item['MACAddr'])
            ipv4_status._wan_ipv4_ipaddr = IPv4Address(item['connIPv4Address'])
            ipv4_status._wan_ipv4_gateway = IPv4Address(item['connIPv4Gateway'])
            ipv4_status.wan_ipv4_conntype = item['name']
            ipv4_status._wan_ipv4_netmask = IPv4Address(item['connIPv4SubnetMask'])
            dns = item['connIPv4DnsServer'].split(',')
            ipv4_status._wan_ipv4_pridns = IPv4Address(dns[0])
            ipv4_status._wan_ipv4_snddns = IPv4Address(dns[1])

        return ipv4_status

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        atr = [f'"primaryEnable":"{int(enable)}"' if 'GUEST' not in str(wifi) else f'"guestEnable":"{int(enable)}"']
        acts = [
            self.ActItem(
                self.ActItem.SET,
                'DEV2_ADT_WIFI_COMMON',
                self.WIFI_SET[wifi],
                attrs=atr),
        ]
        self.req_act(acts)

    def req_act(self, acts: list):
        '''
        Requests ACTs via the cgi_gdpr proxy
        '''

        all_responses = []
        url = self._get_url('cgi_gdpr?9')

        for act in acts:
            attrs_str = ', '.join([attr if ':' in attr else f'"{attr}":""' for attr in act.attrs])
            tp_data = \
                (f'{{"data":{{"stack":"{act.stack}","pstack":"{act.pstack}"{"," + attrs_str if attrs_str else ""}}},'
                 f'"operation":"{act.type}","oid":"{act.oid}"}}')

            code, response = self._request(url, data_str=tp_data, encrypt=True)
            response = response.replace("\r", "").replace("\n", "").replace("\t", "")

            if code != 200:
                error = 'TplinkRouter - EX -  Response with error; Request {} - Response {}'.format(tp_data, response)
                if self._logger:
                    self._logger.debug(error)
                raise ClientError(error)

            try:
                if len(response):
                    json_data = loads(response)
                    if 'data' in json_data:
                        all_responses.append(json_data['data'])
            except ValueError:
                raise ClientError(f"Error trying to convert response to JSON: {response}")

        return response, all_responses

    def _req_login(self) -> None:
        login_data = ('{"data":{"UserName":"%s","Passwd":"%s","Action": "1","stack":"0,0,0,0,0,0",'
                      '"pstack":"0,0,0,0,0,0"},"operation":"cgi","oid":"/cgi/login"}') % (
            b64encode(bytes(self.username, "utf-8")).decode("utf-8"),
            b64encode(bytes(self.password, "utf-8")).decode("utf-8")
        )

        sign, data = self._prepare_data(login_data, True)
        assert len(sign) == 256

        request_data = f"sign={sign}\r\ndata={data}\r\n"

        url = f"{self.host}/cgi_gdpr?9"
        (code, response) = self._request(url, data_str=request_data)
        response = self._encryption.aes_decrypt(response)

        # parse and match return code
        ret_code = self._parse_ret_val(response)
        error = ''
        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
            error = 'TplinkRouter - EX - Login failed, wrong user or password.'
        elif ret_code == self.HTTP_ERR_USER_BAD_REQUEST:
            error = 'TplinkRouter - EX - Login failed. Generic error code: {}'.format(ret_code)
        elif ret_code != self.HTTP_RET_OK:
            error = 'TplinkRouter - EX - Login failed. Unknown error code: {}'.format(ret_code)

        if error:
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)
