from base64 import b64encode
from json import loads, dumps
from datetime import timedelta, datetime
from typing import List
from logging import Logger
from tplinkrouterc6u.common.package_enum import Connection, VPN
from tplinkrouterc6u.common.helper import get_ip, get_mac, get_value
from tplinkrouterc6u.common.dataclass import (
    Firmware,
    Status,
    Device,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
    LTEStatus,
    SMS,
    ServingCell,
    VPNStatus)
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.common.encryption import EncryptionWrapperMRGCMOAEP
from tplinkrouterc6u.client.mr import TPLinkMRClientBase, TPLinkMRClientBaseGCM


# Class for EX series routers which supports old firmwares with AES cipher CBC mode
class TPLinkEXClient(TPLinkMRClientBase):
    CLIENT_TYPES = {
        0: Connection.WIRED,
        1: Connection.HOST_2G,
        2: Connection.GUEST_2G,  # Also 2G for multi ssid
        3: Connection.HOST_5G,
        4: Connection.GUEST_5G,  # Also 5G for multi ssid
        5: Connection.HOST_6G,
        6: Connection.GUEST_6G,  # Also 6G for multi ssid
        # 7 was not found
        8: Connection.IOT_2G,
        9: Connection.IOT_5G,
        10: Connection.HOST_MLO,
    }

    WIFI_SET = {
        Connection.HOST_2G: '1,0,0,0,0,0',
        Connection.HOST_5G: '2,0,0,0,0,0',
        Connection.HOST_6G: '3,0,0,0,0,0',
        Connection.HOST_MLO_2G: '1,0,0,0,0,0',
        Connection.HOST_MLO_5G: '2,0,0,0,0,0',
        Connection.HOST_MLO_6G: '3,0,0,0,0,0',
        Connection.GUEST_2G: '1,0,0,0,0,0',
        Connection.GUEST_5G: '2,0,0,0,0,0',
        Connection.GUEST_6G: '3,0,0,0,0,0',
        Connection.IOT_2G: '1,0,0,0,0,0',
        Connection.IOT_5G: '2,0,0,0,0,0',
        Connection.IOT_6G: '3,0,0,0,0,0',
    }

    # EasyMesh radio index (2nd stack field of DEV2_WIFI_APDEV_ASSOCDEV) -> band; matches WIFI_SET stacks
    EASYMESH_RADIO_TYPES = {
        '1': Connection.HOST_2G,
        '2': Connection.HOST_5G,
        '3': Connection.HOST_6G,
    }

    class ActItem:
        GET = 'go'
        GO = 'go'
        SET = 'so'
        ADD = 'add'
        DEL = 'del'
        DO = 'do'
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

    # Optional multi-WAN / uptime fields; probed separately so firmwares that reject unknown attrs stay safe
    _WAN_DETAIL_ATTRS = ['serviceType', 'connStatusV4', 'X_TP_Uptime']

    def __init__(self, host: str, password: str, username: str = 'user', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self._url_rsa_key = 'cgi/getGDPRParm'
        # Like MR _ipv6_support: ask for serviceType / connStatusV4 / X_TP_Uptime once; latch off on failure
        self._wan_detail_support = True
        # TIM XGB834v (and similar): DEV2 objects only answer after the matching web UI
        # page was GETed. Retry via that page when an act returns no data; latch off only
        # when the page request succeeded and data is still missing (firmware lacks the
        # object). Transient errors keep the flags so the next poll can recover. See #257.
        self._ui_page_retry_status = True
        self._ui_page_retry_map = True
        self._ui_page_retry_dhcp = True
        self._ui_page_retry_leases = True
        self._ui_page_access_quirk = False
        # EasyMesh association tables (VX231v); latch off when the OIDs are missing (e.g. EX920)
        self._easymesh_assoc_support = True

    def supports(self) -> bool:
        try:
            self.authorize()
            return True
        except Exception:
            pass

        return False

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

        if not values or not values[0]:
            raise ValueError('No firmware information received.')

        firmware = Firmware(
            values[0].get('hardwareVersion', ''),
            values[0].get('modelName', ''),
            values[0].get('softwareVersion', '')
        )

        return firmware

    def _select_wan(self, wan: dict | list | None) -> list:
        # Enabled WAN rows to read fields from. Multi-WAN firmwares (e.g. XGB834v) list USB, IPTV and
        # Internet side by side; prefer Connected Internet, then any Internet, then Connected non-IPTV,
        # else the legacy last-enabled behaviour. Several Connected Internet rows: the first wins.
        items = [item for item in self._to_list(wan)
                 if not (int(item.get('enable', '0') or '0') == 0 and wan.__class__ == list)]
        for item in items:
            if 'Internet' in item.get('serviceType', '') and item.get('connStatusV4') == 'Connected':
                return [item]
        for item in items:
            if 'Internet' in item.get('serviceType', ''):
                return [item]
        for item in items:
            if item.get('connStatusV4') == 'Connected' and 'IPTV' not in item.get('serviceType', ''):
                return [item]
        return items

    def _probe_wan_detail(self, attrs: list[str]):
        # Separate DEV2_ADT_WAN request for optional attrs (same idea as MR WAN_IP_CONN IPv6 probe).
        # EX req_act returns one data slot per act; unwrap that slot. Latch off on None/error.
        if not self._wan_detail_support:
            return None
        try:
            _, values = self.req_act([
                self.ActItem(self.ActItem.GL, 'DEV2_ADT_WAN', attrs=list(attrs) + self._WAN_DETAIL_ATTRS),
            ])
            # values is [data]; data None means the firmware omitted the payload
            if values and values[0] is not None:
                return values[0]
            self._wan_detail_support = False
        except Exception:
            self._wan_detail_support = False
        return None

    @staticmethod
    def _act_data_missing(value) -> bool:
        """True when an act replied with success but no usable data block (page ACL / unsupported)."""
        return value is None

    def _request_ui_page(self, page: str) -> None:
        """GET a web UI HTML page to switch DEV2 page-access context (#257)."""
        url = '{}/{}'.format(self.host.rstrip('/'), page.lstrip('/'))
        self._request(url, method='GET')

    def _refetch_acts(self, acts: list) -> list:
        _, values = self.req_act(acts)
        return values if values else []

    def _get_easymesh_controller(self) -> dict | None:
        # LAN MAC/IP of the router itself from its EasyMesh AP device entry (stack 1,0,0,0,0,0).
        # The MAC matches the one DEV2_ADT_LAN reports, so the router keeps its identity.
        try:
            _, values = self.req_act([self.ActItem(self.ActItem.GL, 'DEV2_WIFI_APDEV')])
        except Exception:
            return None
        for val in self._to_list(values[0] if values else None):
            if val.get('stack') == '1,0,0,0,0,0' and val.get('MACAddress') and val.get('X_TP_IPAddress'):
                return {'MACAddress': val['MACAddress'], 'IPAddress': val['X_TP_IPAddress']}
        return None

    def _get_easymesh_devices(self) -> dict:
        # Clients as listed by the EasyMesh controller's Network Map: Wi-Fi stations and wired hosts.
        # Probe once; latch off on error or success-without-data so EX920-style firmwares do not
        # re-hit missing OIDs on every empty host-table poll. Empty lists [] stay supported.
        if not self._easymesh_assoc_support:
            return {}
        try:
            _, values = self.req_act([
                self.ActItem(self.ActItem.GL, 'DEV2_WIFI_APDEV_ASSOCDEV'),
                self.ActItem(self.ActItem.GL, 'DEV2_WIFI_APDEV_ETHASSOCDEV'),
            ])
        except Exception:
            self._easymesh_assoc_support = False
            return {}

        assoc = values[0] if values else None
        eth = values[1] if values and len(values) > 1 else None
        if assoc is None and eth is None:
            self._easymesh_assoc_support = False
            return {}

        devices = {}
        for val in self._to_list(assoc):
            if int(val.get('active', '0') or '0') == 0 or not val.get('MACAddress'):
                continue
            stack = val.get('stack', '').split(',')
            # 3rd stack field is the BSS; only the first (primary SSID) is known to be the host network.
            # Other BSS indexes (guest/IoT) stay UNKNOWN — mapping is unverified on these firmwares.
            if len(stack) > 2 and stack[2] == '1':
                conn = self.EASYMESH_RADIO_TYPES.get(stack[1], Connection.UNKNOWN)
            else:
                conn = Connection.UNKNOWN
            devices[val['MACAddress']] = Device(conn,
                                                get_mac(val['MACAddress']),
                                                get_ip(val.get('X_TP_IPAddress') or '0.0.0.0'),
                                                val.get('X_TP_HostName', ''))
        for val in self._to_list(eth):
            if int(val.get('active', '0') or '0') == 0 or not val.get('MACAddress'):
                continue
            devices[val['MACAddress']] = Device(Connection.WIRED,
                                                get_mac(val['MACAddress']),
                                                get_ip(val.get('IPAddress') or '0.0.0.0'),
                                                val.get('X_TP_HostName', ''))

        return devices

    def get_status(self) -> Status:
        status = Status()
        wan_attrs = ['enable', 'MACAddr', 'connIPv4Address', 'connIPv4Gateway']
        acts = [
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_LAN', attrs=['MACAddress', 'IPAddress']),
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_WAN', attrs=wan_attrs),
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_WIFI_COMMON'),
            self.ActItem(self.ActItem.GL, 'DEV2_HOST_ENTRY',
                         attrs=['active', 'X_TP_LanConnType', 'physAddress', 'IPAddress', 'hostName']),
            self.ActItem(self.ActItem.GO, 'DEV2_MEM_STATUS', attrs=['total', 'free']),
            self.ActItem(self.ActItem.GO, 'DEV2_PROC_STATUS', attrs=['CPUUsage']),
        ]

        _, values = self.req_act(acts)
        if not values:
            values = []
        while len(values) < 6:
            values.append(None)

        # status.htm exposes MEM/PROC; networkMap.htm exposes LAN/WAN/Wi-Fi/hosts.
        # Request status first, then map last so the session ends on the home page.
        used_status_page = False
        if self._ui_page_retry_status and (
                self._act_data_missing(values[4]) or self._act_data_missing(values[5])):
            try:
                self._request_ui_page('main/status.htm')
                used_status_page = True
                mem_proc = self._refetch_acts([acts[4], acts[5]])
                if len(mem_proc) > 0 and not self._act_data_missing(mem_proc[0]):
                    values[4] = mem_proc[0]
                    self._ui_page_access_quirk = True
                if len(mem_proc) > 1 and not self._act_data_missing(mem_proc[1]):
                    values[5] = mem_proc[1]
                    self._ui_page_access_quirk = True
                if self._act_data_missing(values[4]) and self._act_data_missing(values[5]):
                    self._ui_page_retry_status = False
            except Exception as e:
                if self._logger:
                    self._logger.debug('TplinkRouter - EX - UI page retry (status.htm) failed: %s', e)

        map_needed = (
                self._act_data_missing(values[0])
                or self._act_data_missing(values[2])
                or self._act_data_missing(values[3]))
        if self._ui_page_retry_map and map_needed:
            try:
                self._request_ui_page('main/networkMap.htm')
                used_status_page = False
                map_vals = self._refetch_acts(acts[0:4])
                recovered = False
                for i in range(min(4, len(map_vals))):
                    if not self._act_data_missing(map_vals[i]):
                        if self._act_data_missing(values[i]):
                            recovered = True
                        values[i] = map_vals[i]
                if recovered:
                    self._ui_page_access_quirk = True
                if self._act_data_missing(values[2]) and self._act_data_missing(values[3]):
                    # Still no Wi-Fi/hosts after the map page → firmware lacks them
                    self._ui_page_retry_map = False
            except Exception as e:
                if self._logger:
                    self._logger.debug('TplinkRouter - EX - UI page retry (networkMap.htm) failed: %s', e)
        elif used_status_page and self._ui_page_access_quirk:
            # MEM/PROC came from status.htm while map data was already in hand; restore
            # the usual home-page session context without another act round-trip.
            try:
                self._request_ui_page('main/networkMap.htm')
            except Exception:
                pass

        if values and self._act_data_missing(values[0]):
            # Same EasyMesh controller firmwares may also answer DEV2_ADT_LAN without data
            values[0] = self._get_easymesh_controller()

        if not values or self._act_data_missing(values[0]):
            raise ClientError('TplinkRouter - EX - DEV2_ADT_LAN returned no data')

        if values[0].__class__ == list:
            values[0] = values[0][0]

        status._lan_macaddr = get_mac(values[0]['MACAddress'])
        status._lan_ipv4_addr = get_ip(values[0]['IPAddress'])

        wan = values[1] if len(values) > 1 else None
        wan_detail = self._probe_wan_detail(wan_attrs)
        if wan_detail is not None:
            wan = wan_detail
        for item in self._select_wan(wan):
            status._wan_macaddr = get_mac(item['MACAddr']) if item.get('MACAddr') else None
            status._wan_ipv4_addr = get_ip(item['connIPv4Address']) if item.get('connIPv4Address') else None
            status._wan_ipv4_gateway = get_ip(item['connIPv4Gateway']) if item.get('connIPv4Address') else None
            uptime = item.get('X_TP_Uptime', '')
            status.wan_ipv4_uptime = int(uptime) if str(uptime or '').isdigit() else None

        if len(values) > 2 and values[2]:
            networks = values[2] if values[2].__class__ == list else [values[2]]

            if len(networks) > 0:
                status.wifi_2g_enable = bool(int(networks[0]['primaryEnable']))
                status.guest_2g_enable = (
                    bool(int(networks[0]['guestEnable']))
                    if networks[0].get('guestEnable')
                    else None
                )
                status.iot_2g_enable = (
                    bool(int(networks[0]['ioTssidEnable']))
                    if networks[0].get('ioTssidEnable')
                    else None
                )
                status.wifi_mlo_2g_enable = (
                    bool(int(networks[0]['mloEnable']))
                    if networks[0].get('mloEnable')
                    else None
                )
            if len(networks) > 1:
                status.wifi_5g_enable = bool(int(networks[1]['primaryEnable']))
                status.guest_5g_enable = (
                    bool(int(networks[1]['guestEnable']))
                    if networks[1].get('guestEnable')
                    else None
                )
                status.iot_5g_enable = (
                    bool(int(networks[1]['ioTssidEnable']))
                    if networks[1].get('ioTssidEnable')
                    else None
                )
                status.wifi_mlo_5g_enable = (
                    bool(int(networks[1]['mloEnable']))
                    if networks[1].get('mloEnable')
                    else None
                )
            if len(networks) > 2:
                status.wifi_6g_enable = bool(int(networks[2]['primaryEnable']))
                status.guest_6g_enable = (
                    bool(int(networks[2]['guestEnable']))
                    if networks[2].get('guestEnable')
                    else None
                )
                status.iot_6g_enable = (
                    bool(int(networks[2]['ioTssidEnable']))
                    if networks[2].get('ioTssidEnable')
                    else None
                )
                status.wifi_mlo_6g_enable = (
                    bool(int(networks[2]['mloEnable']))
                    if networks[2].get('mloEnable')
                    else None
                )

        devices = {}
        for val in self._to_list(values[3] if len(values) > 3 else None):
            if int(val['active']) == 0:
                continue
            conn = self.CLIENT_TYPES.get(int(val['X_TP_LanConnType']), Connection.UNKNOWN)
            devices[val['physAddress']] = Device(conn,
                                                 get_mac(val['physAddress']),
                                                 get_ip(val['IPAddress']),
                                                 val['hostName'])

        # Some EasyMesh controller firmwares (e.g. VX231v 231.0.25) stop filling DEV2_HOST_ENTRY while
        # the web UI keeps listing clients from the EasyMesh association tables. Only consulted when
        # the host table is empty, so routers with a populated host table are unaffected.
        if not devices:
            devices = self._get_easymesh_devices()

        for device in devices.values():
            conn = device.type
            if conn == Connection.WIRED:
                status.wired_total += 1
            elif conn.is_guest_wifi():
                status.guest_clients_total += 1
            elif conn.is_host_wifi():
                status.wifi_clients_total += 1
            elif conn.is_iot():
                if status.iot_clients_total is None:
                    status.iot_clients_total = 0
                status.iot_clients_total += 1
            else:
                # Unknown / unmapped X_TP_LanConnType — still count toward totals
                status.wifi_clients_total += 1

        # Some firmwares (e.g. EX920) leave DEV2_MEM_STATUS / DEV2_PROC_STATUS
        # empty (success with no data); slots stay None so indexes do not shift.
        if len(values) > 4 and values[4]:
            total = int(values[4]['total'])
            free = int(values[4]['free'])
            status.mem_usage = ((total - free) / total)

        if len(values) > 5 and values[5]:
            status.cpu_usage = int(values[5]['CPUUsage']) / 100

        status.devices = list(devices.values())
        status.clients_total = (
            status.wired_total
            + status.wifi_clients_total
            + status.guest_clients_total
            + (status.iot_clients_total or 0)
        )

        return status

    def get_ipv4_reservations(self) -> [IPv4Reservation]:
        acts = [
            self.ActItem(self.ActItem.GL, 'DEV2_DHCPV4_POOL_STATICADDR', attrs=['enable', 'chaddr', 'yiaddr']),
        ]
        _, values = self.req_act(acts)
        data = values[0] if values else None

        # Only dhcp.htm (and a few siblings) expose DEV2_DHCPV4_POOL_STATICADDR on
        # page-ACL firmwares; retry once then latch off when still empty.
        if self._act_data_missing(data) and self._ui_page_retry_dhcp:
            try:
                self._request_ui_page('main/dhcp.htm')
                values = self._refetch_acts(acts)
                data = values[0] if values else None
                if not self._act_data_missing(data):
                    self._ui_page_access_quirk = True
                else:
                    self._ui_page_retry_dhcp = False
            except Exception as e:
                if self._logger:
                    self._logger.debug('TplinkRouter - EX - UI page retry (dhcp.htm) failed: %s', e)

        ipv4_reservations = []
        for item in self._to_list(data):
            ipv4_reservations.append(
                IPv4Reservation(
                    get_mac(item['chaddr']),
                    get_ip(item['yiaddr']),
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
        data = values[0] if values else None

        if self._act_data_missing(data) and self._ui_page_retry_leases:
            try:
                self._request_ui_page('main/networkMap.htm')
                values = self._refetch_acts(acts)
                data = values[0] if values else None
                if not self._act_data_missing(data):
                    self._ui_page_access_quirk = True
                else:
                    self._ui_page_retry_leases = False
            except Exception as e:
                if self._logger:
                    self._logger.debug('TplinkRouter - EX - UI page retry (networkMap.htm/leases) failed: %s', e)

        dhcp_leases = []
        for item in self._to_list(data):
            lease_time = item['leaseTimeRemaining']
            dhcp_leases.append(
                IPv4DHCPLease(
                    get_mac(item['physAddress']),
                    get_ip(item['IPAddress']),
                    item['hostName'],
                    str(timedelta(seconds=int(lease_time))) if (lease_time.isdigit()
                                                                and int(lease_time)) > 0 else 'Permanent',
                ))

        # EasyMesh controllers may leave DEV2_HOST_ENTRY empty; association tables have no lease
        # remaining, so report Permanent (same as a static/zero leaseTimeRemaining row).
        if not dhcp_leases:
            for device in self._get_easymesh_devices().values():
                dhcp_leases.append(
                    IPv4DHCPLease(device.macaddress, device.ipaddress, device.hostname, 'Permanent'))

        return dhcp_leases

    def get_ipv4_status(self) -> IPv4Status:
        wan_attrs = ['enable', 'MACAddr', 'connIPv4Address', 'connIPv4Gateway', 'name', 'connIPv4SubnetMask',
                     'connIPv4DnsServer']
        acts = [
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_LAN',
                         attrs=['MACAddress', 'IPAddress', 'IPSubnetMask', 'DHCPv4Enable']),
            self.ActItem(self.ActItem.GL, 'DEV2_ADT_WAN', attrs=wan_attrs),
        ]
        _, values = self.req_act(acts)

        if values and not values[0]:
            # Same EasyMesh controller path as get_status() when DEV2_ADT_LAN has no data
            values[0] = self._get_easymesh_controller()

        if values and values[0] and values[0].__class__ == list and len(values[0]) > 0:
            values[0] = values[0][0]

        ipv4_status = IPv4Status()
        ipv4_status._lan_macaddr = get_mac(get_value(values, [0, 'MACAddress'], '00:00:00:00:00:00'))
        ipv4_status._lan_ipv4_ipaddr = get_ip(get_value(values, [0, 'IPAddress'], '0.0.0.0'))
        ipv4_status._lan_ipv4_netmask = get_ip(get_value(values, [0, 'IPSubnetMask'], '0.0.0.0'))
        ipv4_status.lan_ipv4_dhcp_enable = bool(int(get_value(values, [0, 'DHCPv4Enable'], '0')))

        wan = values[1] if values and len(values) > 1 else None
        wan_detail = self._probe_wan_detail(wan_attrs)
        if wan_detail is not None:
            wan = wan_detail
        for item in self._select_wan(wan):
            ipv4_status._wan_macaddr = get_mac(get_value(item, ['MACAddr'], '00:00:00:00:00:00'))
            ipv4_status._wan_ipv4_ipaddr = get_ip(get_value(item, ['connIPv4Address'], '0.0.0.0'))
            ipv4_status._wan_ipv4_gateway = get_ip(get_value(item, ['connIPv4Gateway'], '0.0.0.0'))
            ipv4_status._wan_ipv4_conntype = get_value(item, ['name'], '')
            ipv4_status._wan_ipv4_netmask = get_ip(get_value(item, ['connIPv4SubnetMask'], '0.0.0.0'))
            dns = get_value(item, ['connIPv4DnsServer'], '').split(',')
            ipv4_status._wan_ipv4_pridns = get_ip(dns[0] if len(dns) > 0 else '0.0.0.0')
            ipv4_status._wan_ipv4_snddns = get_ip(dns[1] if len(dns) > 1 else '0.0.0.0')

        return ipv4_status

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        if wifi not in self.WIFI_SET:
            raise ClientException(f'Unsupported wifi connection for EX set_wifi: {wifi}')
        if wifi.is_guest_wifi():
            attr_key = 'guestEnable'
        elif wifi.is_iot():
            attr_key = 'ioTssidEnable'
        elif wifi.is_mlo_switch():
            attr_key = 'mloEnable'
        else:
            attr_key = 'primaryEnable'
        atr = [f'"{attr_key}":"{int(enable)}"']
        acts = [
            self.ActItem(
                self.ActItem.SET,
                'DEV2_ADT_WIFI_COMMON',
                self.WIFI_SET[wifi],
                attrs=atr),
        ]
        self.req_act(acts)

    def get_lte_status(self) -> LTEStatus:
        status = LTEStatus()
        acts = [
            self.ActItem(self.ActItem.GET, 'DEV2_LTE_LINK_CFG', '1,0,0,0,0,0',
                         attrs=['enable', 'connectStatus', 'networkType', 'simStatus']),
            self.ActItem(self.ActItem.GET, 'DEV2_XTP_LTE_INTF_CFG', '1,0,0,0,0,0',
                         attrs=['totalStatistics', 'curRxSpeed', 'curTxSpeed']),
            self.ActItem(self.ActItem.GET, 'DEV2_LTE_NET_STATUS', '1,0,0,0,0,0',
                         attrs=['smsUnreadCount', 'sigLevel', 'rfInfoRsrp', 'rfInfoRsrq', 'rfInfoSnr']),
            self.ActItem(self.ActItem.GET, 'DEV2_LTE_PROF_STAT', '1,0,0,0,0,0', attrs=['ispName']),
        ]
        _, values = self.req_act(acts)

        status.enable = int(values[0]['enable'])
        status.connect_status = int(values[0]['connectStatus'])
        status.network_type = int(values[0]['networkType'])
        status.sim_status = int(values[0]['simStatus'])

        status.total_statistics = int(float(values[1]['totalStatistics']))
        status.cur_rx_speed = int(values[1]['curRxSpeed'])
        status.cur_tx_speed = int(values[1]['curTxSpeed'])

        status.sms_unread_count = int(values[2]['smsUnreadCount'])
        status.sig_level = int(values[2]['sigLevel'])
        status.rsrp = int(values[2]['rfInfoRsrp'])
        status.rsrq = int(values[2]['rfInfoRsrq'])
        status.snr = int(values[2]['rfInfoSnr'])

        status.isp_name = values[3]['ispName']

        try:
            acts = [self.ActItem(self.ActItem.GL, 'DEV2_LTE_SERVING_CELL_INFO',
                                 attrs=['networkType', 'signalStrength', 'SSRSRP', 'SSRSRQ', 'SSSINR'])]
            _, values = self.req_act(acts)

            # Each entry in serving_cell_info_list is one RAT. Match on active networkType.
            active_serving_cell = next(
                (c for c in self._to_list(values[0] if values else None)
                 if int(c.get('networkType', -1)) == status.network_type),
                None,
            )
            if active_serving_cell is not None:
                # Per-RAT signal from DEV2_LTE_SERVING_CELL_INFO
                status.sig_level = int(active_serving_cell['signalStrength'])
                status.rsrp = int(active_serving_cell['SSRSRP'])
                status.rsrq = int(active_serving_cell['SSRSRQ'])
                status.snr = int(active_serving_cell['SSSINR'])
        except Exception:
            pass

        return status

    def send_sms(self, phone_number: str, message: str) -> None:
        if '\r' in phone_number or '\n' in phone_number:
            raise ClientException('phone_number must not contain newline characters')

        acts = [
            self.ActItem(
                self.ActItem.SET, 'DEV2_LTE_SMS_SENDNEWMSG', attrs=[
                    '"index":"1"',
                    f'"to":{dumps(phone_number)}',
                    f'"textContent":{dumps(message)}',
                ]),
        ]
        self.req_act(acts)

    def _fetch_sms_entries(self) -> list[tuple[int, dict]]:
        acts = [
            self.ActItem(self.ActItem.GO, 'DEV2_LTE_SMS_RECVMSGBOX'),
        ]
        _, values = self.req_act(acts)

        total_number = int(values[0]['totalNumber']) if values and values[0] else 0
        if total_number == 0:
            return []

        sms_attrs = ['index', 'from', 'content', 'receivedTime', 'unread']
        page_size = 8
        num_pages = (total_number + page_size - 1) // page_size

        entries = []
        for page in range(1, num_pages + 1):
            acts = [
                self.ActItem(
                    self.ActItem.SET, 'DEV2_LTE_SMS_RECVMSGBOX',
                    attrs=[f'"pageNumber":"{page}"']),
                self.ActItem(
                    self.ActItem.GL, 'DEV2_LTE_SMS_RECVMSGENTRY', attrs=sms_attrs),
            ]
            _, values = self.req_act(acts)

            # Slot 0 is SET (often no data → None); slot 1 is the GL entry list.
            entry_data = values[1] if len(values) > 1 else (values[0] if values else None)
            for item in self._to_list(entry_data):
                entries.append((page, item))

        return entries

    def _resolve_sms(self, sms: SMS) -> tuple[int, str]:
        for page, item in self._fetch_sms_entries():
            if int(item['index']) == sms.id:
                return page, item['stack']

        raise ClientError(f'SMS not found: index {sms.id}')

    def get_sms(self) -> List[SMS]:
        messages = []
        for _, item in self._fetch_sms_entries():
            messages.append(
                SMS(
                    int(item['index']),
                    item['from'],
                    item['content'],
                    datetime.fromisoformat(item['receivedTime']),
                    item['unread'] == '1',
                )
            )

        return messages

    def set_sms_read(self, sms: SMS) -> None:
        page, stack = self._resolve_sms(sms)
        acts = [
            self.ActItem(
                self.ActItem.SET, 'DEV2_LTE_SMS_RECVMSGBOX',
                attrs=[f'"pageNumber":"{page}"']),
            self.ActItem(
                self.ActItem.SET, 'DEV2_LTE_SMS_RECVMSGENTRY',
                stack=stack,
                attrs=['"unread":"0"'],
            ),
        ]
        self.req_act(acts)

    def delete_sms(self, sms: SMS) -> None:
        page, stack = self._resolve_sms(sms)
        acts = [
            self.ActItem(
                self.ActItem.SET, 'DEV2_LTE_SMS_RECVMSGBOX',
                attrs=[f'"pageNumber":"{page}"']),
            self.ActItem(
                self.ActItem.DO, 'DEV2_LTE_SMS_RECVMSGENTRY',
                stack=stack,
            ),
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
                if not response:
                    # Keep one slot per act so callers can index by request order.
                    all_responses.append(None)
                    continue
                json_data = loads(response)
                # Firmwares such as EX920 may return success with no "data" key;
                # dropping those replies used to shift positional indexes (HA #393).
                all_responses.append(
                    json_data.get('data') if isinstance(json_data, dict) else None)
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
        # One RSA block = len(nn) hex chars; no-padding uses 2 blocks (256),
        # OAEP on a 512-bit key uses 5 (640). Accept any whole-block length.
        assert self._nn and len(sign) % len(self._nn) == 0

        request_data = f"sign={sign}\r\ndata={data}\r\n"

        url = f"{self.host}/cgi_gdpr?9"
        (code, response) = self._request(url, data_str=request_data)
        response = self._encryption.aes_decrypt(response)

        # parse and match return code
        ret_code = self._parse_ret_val(response)
        error = ''
        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
            error = ('TplinkRouter - EX - Login failed, wrong user or password. '
                     'Try to pass user instead of admin in username')
        elif ret_code == self.HTTP_ERR_USER_BAD_REQUEST:
            error = 'TplinkRouter - EX - Login failed. Generic error code: {}'.format(ret_code)
        elif ret_code != self.HTTP_RET_OK:
            error = 'TplinkRouter - EX - Login failed. Unknown error code: {}'.format(ret_code)

        if error:
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def get_vpn_status(self) -> VPNStatus:
        status = VPNStatus()
        acts = [
            self.ActItem(self.ActItem.GET, 'DEV2_OPENVPN', attrs=['enable']),
            self.ActItem(self.ActItem.GET, 'DEV2_PPTPVPN', attrs=['enable']),
            self.ActItem(self.ActItem.GL, 'DEV2_OVPN_CLIENT', attrs=['connAct']),
            self.ActItem(self.ActItem.GL, 'DEV2_PVPN_CLIENT', attrs=['connAct']),
        ]
        _, values = self.req_act(acts)

        status.openvpn_enable = bool(values and values[0] and values[0].get('enable') == '1')
        status.pptpvpn_enable = bool(
            values and len(values) > 1 and values[1] and values[1].get('enable') == '1')

        for item in self._to_list(values[2] if values and len(values) > 2 else None):
            if item['connAct'] == '1':
                status.openvpn_clients_total += 1

        for item in self._to_list(values[3] if values and len(values) > 3 else None):
            if item['connAct'] == '1':
                status.pptpvpn_clients_total += 1

        return status

    def set_vpn(self, vpn: VPN, enable: bool) -> None:
        acts = [
            self.ActItem(self.ActItem.SET, "DEV2_" + vpn.value, attrs=[f'"enable":"{int(enable)}"'])
        ]

        self.req_act(acts)

    def get_lte_serving_cells(self) -> List[ServingCell]:
        acts = [self.ActItem(self.ActItem.GL, 'DEV2_LTE_SERVING_CELL_INFO', attrs=[
            'networkType', 'cellConnectionStatus', 'band', 'ARFCN', 'downBandWidth', 'downFreq',
            'downlinkModType', 'uplinkModType', 'CQI', 'RI', 'numRbs', 'RSRP', 'RSRQ',
        ])]
        _, values = self.req_act(acts)
        raw_cells = self._to_list(values[0] if values else None)

        def clean_int(raw: str | None) -> int | None:
            if raw is None or raw == '' or raw == '268435455':
                return None
            return int(raw)

        cells = []
        for c in raw_cells:
            if c.get('cellConnectionStatus') != '1':
                continue
            bandwidth = clean_int(c.get('downBandWidth'))
            cells.append(ServingCell(
                network_type=int(c['networkType']),
                band=int(c['band']),
                arfcn=int(c['ARFCN']),
                downlink_bandwidth=bandwidth // 1000 if bandwidth is not None else None,
                downlink_frequency=clean_int(c.get('downFreq')),
                downlink_modulation=c.get('downlinkModType') or None,
                uplink_modulation=c.get('uplinkModType') or None,
                cqi=clean_int(c.get('CQI')),
                ri=clean_int(c.get('RI')),
                resource_blocks=clean_int(c.get('numRbs')),
                rsrp=clean_int(c.get('RSRP')),
                rsrq=clean_int(c.get('RSRQ')),
            ))
        return cells


# Class for EX series routers which supports AES cipher GCM mode
class TPLinkEXClientGCM(TPLinkMRClientBaseGCM, TPLinkEXClient):

    def _req_login(self) -> None:
        login_data = ('{"data":{"UserName":"%s","Passwd":"%s","Action": "1","stack":"0,0,0,0,0,0",'
                      '"pstack":"0,0,0,0,0,0"},"operation":"cgi","oid":"/cgi/login"}') % (
            b64encode(bytes(self.username, "utf-8")).decode("utf-8"),
            b64encode(bytes(self.password, "utf-8")).decode("utf-8")
        )

        sign, data, tag = self._prepare_data(login_data, True)
        # One RSA block = len(nn) hex chars; no-padding uses 2 blocks (256),
        # OAEP on a 512-bit key uses 5 (640). Accept any whole-block length.
        assert self._nn and len(sign) % len(self._nn) == 0

        request_data = f"sign={sign}\r\ndata={data}\r\ntag={tag}\r\n"

        url = f"{self.host}/cgi_gdpr?9"
        (code, response) = self._request(url, data_str=request_data)
        response = self._encryption.aes_decrypt(response)

        # parse and match return code
        ret_code = self._parse_ret_val(response)
        error = ''
        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
            error = ('TplinkRouter - EX - Login failed, wrong user or password. '
                     'Try to pass user instead of admin in username')
        elif ret_code == self.HTTP_ERR_USER_BAD_REQUEST:
            error = 'TplinkRouter - EX - Login failed. Generic error code: {}'.format(ret_code)
        elif ret_code != self.HTTP_RET_OK:
            error = 'TplinkRouter - EX - Login failed. Unknown error code: {}'.format(ret_code)

        if error:
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)


# Class for EX series routers with AES-GCM and RSA-OAEP signatures (e.g. EX920)
class TPLinkEXClientGCMOAEP(TPLinkEXClientGCM):
    """
    EX GCM client for firmwares that sign with RSA-OAEP instead of raw RSA
    (HA #393 / EX920). Session AES-GCM is unchanged; only the login/request
    signature padding differs. Default username remains ``user`` (password-only
    UI on these models).
    """

    def __init__(self, host: str, password: str, username: str = 'user', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._encryption = EncryptionWrapperMRGCMOAEP()
