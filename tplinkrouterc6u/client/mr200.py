import base64
from tplinkrouterc6u.client.mr import TPLinkMRClient
from Crypto.PublicKey import RSA
from binascii import hexlify
from Crypto.Cipher import PKCS1_v1_5
from re import search
from time import sleep
from datetime import timedelta, datetime
from macaddress import EUI48
from ipaddress import IPv4Address
from tplinkrouterc6u.common.helper import get_ip, get_mac, get_value
from tplinkrouterc6u.common.package_enum import Connection, VPN
from tplinkrouterc6u.common.dataclass import (
    Firmware,
    Status,
    Device,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
    SMS,
    LTEStatus,
    VPNStatus,
)
from tplinkrouterc6u.common.exception import ClientException, ClientError, AuthorizeError


class TPLinkMR200Client(TPLinkMRClient):

    def authorize(self) -> None:
        self.req.headers = {'referer': f'{self.host}/', 'origin': self.host}
        params = self.__get_params()

        # Construct the RSA public key manually using modulus (n) and exponent (e)
        n = int(params["nn"])
        e = int(params["ee"])
        pub_key = RSA.construct((n, e))

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

    def get_firmware(self) -> Firmware:
        acts = [
            self.ActItem(self.ActItem.GET, 'IGD_DEV_INFO')
        ]
        _, values = self.req_act(acts)

        firmware = Firmware(values.get('hardwareVersion', ''), values.get('modelName', ''),
                            values.get('softwareVersion', ''))

        return firmware

    def get_status(self) -> Status:
        status = Status()
        acts = [
            self.ActItem(self.ActItem.GS, 'LAN_IP_INTF'),
            self.ActItem(self.ActItem.GS, 'WAN_IP_CONN'),
            self.ActItem(self.ActItem.GL, 'LAN_WLAN'),
            self.ActItem(self.ActItem.GL, 'LAN_WLAN_GUESTNET'),
            self.ActItem(self.ActItem.GL, 'LAN_HOST_ENTRY'),
            self.ActItem(self.ActItem.GS, 'LAN_WLAN_ASSOC_DEV'),
        ]
        _, values = self.req_act(acts)

        # Safe access for '0'
        data0 = values.get('0', values)  # fallback to full dict if '0' key doesn't exist
        if isinstance(data0, list):
            data0 = data0[0]

        status._lan_macaddr = EUI48(data0['X_TP_MACAddress'])
        status._lan_ipv4_addr = IPv4Address(data0['IPInterfaceIPAddress'])

        for item in self._to_list(values.get('1')):
            if int(item.get('enable', 1)) == 0:
                continue
            status._wan_macaddr = EUI48(item.get('MACAddress')) if item.get('MACAddress') else None
            status._wan_ipv4_addr = IPv4Address(item.get('externalIPAddress'))
            status._wan_ipv4_gateway = IPv4Address(item.get('defaultGateway'))
            status.conn_type = item.get('name', '')

        # Wifi status
        wifi_data = values.get('2', {})
        if isinstance(wifi_data, dict):
            status.wifi_2g_enable = bool(int(wifi_data.get('enable', 0)))
        elif isinstance(wifi_data, list):
            status.wifi_2g_enable = bool(int(wifi_data[0].get('enable', 0)))
            if len(wifi_data) > 1:
                status.wifi_5g_enable = bool(int(wifi_data[1].get('enable', 0)))

        guest_data = values.get('3', {})
        if isinstance(guest_data, dict):
            status.guest_2g_enable = bool(int(guest_data.get('enable', 0)))
        elif isinstance(guest_data, list):
            status.guest_2g_enable = bool(int(guest_data[0].get('enable', 0)))
            if len(guest_data) > 1:
                status.guest_5g_enable = bool(int(guest_data[1].get('enable', 0)))

        # Devices
        devices = {}
        for val in self._to_list(values.get('4')):
            if int(val.get('active', 0)) == 0:
                continue
            conn = self.CLIENT_TYPES.get(int(val.get('X_TP_ConnType', -1)))
            if conn is None:
                continue
            elif conn == Connection.WIRED:
                status.wired_total += 1
            elif conn.is_guest_wifi():
                status.guest_clients_total += 1
            elif conn.is_host_wifi():
                status.wifi_clients_total += 1
            devices[val['MACAddress']] = Device(
                conn,
                EUI48(val['MACAddress']),
                IPv4Address(val['IPAddress']),
                val.get('hostName', '')
            )

        for val in self._to_list(values.get('5')):
            mac = val.get('associatedDeviceMACAddress')
            if mac not in devices:
                status.wifi_clients_total += 1
                devices[mac] = Device(
                    Connection.HOST_2G,
                    EUI48(mac),
                    IPv4Address('0.0.0.0'),
                    ''
                )
            devices[mac].packets_sent = int(val.get('X_TP_TotalPacketsSent', 0))
            devices[mac].packets_received = int(val.get('X_TP_TotalPacketsReceived', 0))

        status.devices = list(devices.values())
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total

        return status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        acts = [
            self.ActItem(self.ActItem.GL, 'LAN_DHCP_STATIC_ADDR'),
        ]
        _, values = self.req_act(acts)

        ipv4_reservations = []
        for item in self._to_list(values):
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
            self.ActItem(self.ActItem.GL, 'LAN_HOST_ENTRY'),
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
            self.ActItem(self.ActItem.GS, 'LAN_IP_INTF'),
            self.ActItem(self.ActItem.GET, 'LAN_HOST_CFG', '1,0,0,0,0,0'),
            self.ActItem(self.ActItem.GS, 'WAN_IP_CONN'),
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
        acts = [
            self.ActItem(
                self.ActItem.SET,
                'LAN_WLAN' if wifi in [Connection.HOST_2G, Connection.HOST_5G] else 'LAN_WLAN_MSSIDENTRY',
                self.WIFI_SET[wifi],
                attrs=['enable={}'.format(int(enable))]),
        ]
        self.req_act(acts)

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
        '''
        Logs out from the host
        '''
        if self._token is None:
            return

        acts = [
            # 8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n
            self.ActItem(self.ActItem.CGI, '/cgi/logout')
        ]

        response, _ = self.req_act(acts)
        ret_code = self._parse_ret_val(response)

        if ret_code == self.HTTP_RET_OK:
            del self.req.headers["TokenID"]

    def send_sms(self, phone_number: str, message: str) -> None:
        acts = [
            self.ActItem(
                self.ActItem.SET, 'LTE_SMS_SENDNEWMSG', attrs=[
                    'index=1',
                    'to={}'.format(phone_number),
                    'textContent={}'.format(message),
                ]),
        ]
        self.req_act(acts)

    def get_sms(self) -> [SMS]:
        acts = [
            self.ActItem(
                self.ActItem.SET, 'LTE_SMS_RECVMSGBOX', attrs=['PageNumber=1']),
            self.ActItem(
                self.ActItem.GL, 'LTE_SMS_RECVMSGENTRY'),
        ]
        _, values = self.req_act(acts)

        messages = []
        if values:
            i = 1
            for item in self._to_list(values.get('1')):
                messages.append(
                    SMS(
                        i, item['from'], item['content'], datetime.fromisoformat(item['receivedTime']),
                        item['unread'] == '1'
                    )
                )
                i += 1

        return messages

    def set_sms_read(self, sms) -> None:
        sms_id = sms.id if hasattr(sms, 'id') else sms
        acts = [
            self.ActItem(
                self.ActItem.SET, 'LTE_SMS_RECVMSGENTRY', f'{sms_id},0,0,0,0,0', attrs=['unread=0']),
        ]
        self.req_act(acts)

    def delete_sms(self, sms) -> None:
        sms_id = sms.id if hasattr(sms, 'id') else sms
        acts = [
            self.ActItem(
                self.ActItem.DEL, 'LTE_SMS_RECVMSGENTRY', f'{sms_id},0,0,0,0,0'),
        ]
        self.req_act(acts)

    def send_ussd(self, command: str) -> str:
        acts = [
            self.ActItem(
                self.ActItem.SET, 'LTE_USSD', attrs=[
                    'action=1',
                    f"reqContent={command}",
                ]),
        ]
        self.req_act(acts)

        status = '0'
        while status == '0':
            sleep(1)
            acts = [
                self.ActItem(self.ActItem.GET, 'LTE_USSD'),
            ]
            _, values = self.req_act(acts)

            status = values.get('ussdStatus', '2')

            if status == '1':
                return values.get('response')
            elif status == '2':
                raise ClientError('Cannot send USSD!')

    def get_lte_status(self) -> LTEStatus:
        status = LTEStatus()
        
        _, link_data = self.req_act([
            self.ActItem(self.ActItem.GET, 'WAN_LTE_LINK_CFG', '2,1,0,0,0,0')
        ])
        _, intf_data = self.req_act([
            self.ActItem(self.ActItem.GET, 'WAN_LTE_INTF_CFG', '2,0,0,0,0,0')
        ])
        _, wan_data = self.req_act([
            self.ActItem(self.ActItem.GET, 'LTE_WAN_CFG', '2,1,0,0,0,0')
        ])
       
        status.enable = link_data.get('enable', 0)
        status.connect_status = link_data.get('connectStatus', 0)
        status.network_type = link_data.get('networkType', 0)
        status.sim_status = link_data.get('simStatus', 0)
        status.sig_level = link_data.get('signalStrength', 0)
        
        status.total_statistics = intf_data.get('totalStatistics', 0)
        status.cur_rx_speed = intf_data.get('curRxSpeed', 0)
        status.cur_tx_speed = intf_data.get('curTxSpeed', 0)
        
        status.isp_name = wan_data.get('profileName', '')

        sms_list = self.get_sms()
        status.sms_unread_count = sum(1 for m in sms_list if getattr(m, 'unread', False))

        return status

    def __get_params(self, retry=False):
        try:
            r = self.req.get(f"{self.host}/cgi/getParm", timeout=5)
            result = {}
            for line in r.text.splitlines()[0:2]:
                match = search(r"var (.*)=\"(.*)\"", line)
                result[match.group(1)] = int(match.group(2), 16)
            return result
        except Exception:
            if not retry:
                return self.__get_params(True)
            raise ClientException()

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
