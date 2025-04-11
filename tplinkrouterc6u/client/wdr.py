import base64
from ipaddress import IPv4Address
from requests import get, Response
from logging import Logger
from macaddress import EUI48
from tplinkrouterc6u.common.helper import get_ip
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.exception import ClientError
from tplinkrouterc6u.common.dataclass import (
    Firmware,
    Status,
    Device,
    IPv4Reservation,
    IPv4DHCPLease,
    IPv4Status,
)
from tplinkrouterc6u.client_abstract import AbstractRouter

from dataclasses import dataclass
from html.parser import HTMLParser

dataUrls = {
    "check": "/StatusRpm.htm",
    "summary": "/StatusRpm.htm",
    "netWan": "/WanDynamicIpCfgRpm.htm?wan=0",
    "netLan": "/NetworkCfgRpm.htm",
    # 'macClone': "",
    # WIFI
    "dualBand": "/WlanBandRpm.htm",
    # 2.4 Ghz"
    "w24settings": "/WlanNetworkRpm.htm",
    "w24wps": "/WpsCfgRpm.htm",
    "w24sec": "/WlanSecurityRpm.htm",
    "w24macflt": "/WlanMacFilterRpm.htm",
    "w24adv": "/WlanAdvRpm.htm",
    "w24stations": "/WlanStationRpm.htm?Page=1",
    # 5.0 Ghz
    "w50settings": "/WlanNetworkRpm_5g.htm",
    "w50wps": "/WpsCfgRpm_5g.htm",
    "w50sec": "/WlanSecurityRpm_5g.htm",
    "w50macflt": "/WlanMacFilterRpm_5g.htm",
    "w50adv": "/WlanAdvRpm_5g.htm",
    "w50stations": "/WlanStationRpm_5g.htm?Page=1",
    # Guest Network
    "wgsettings": "/GuestNetWirelessCfgRpm.htm",
    "wgshare": "/GuestNetUsbCfgRpm.htm",
    # DHCP
    "dhcpconfig": "/LanDhcpServerRpm.htm",
    "dhcplease": "/AssignedIpAddrListRpm.htm",
    "dhcpreserve": "/FixMapCfgRpm.htm",
    # Referer
    "defReferer": "/MenuRpm.htm",
    # routing
    "sysroute": "/SysRouteTableRpm.htm",
    "portFwd": "/VirtualServerRpm.htm",
    "upnpFwd": "/UpnpCfgRpm.htm",
    # Reboot
    "reboot": "/SysRebootHelpRpm.htm",
}


def defaultHeaders():
    # default headers for all requests
    return {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "User-Agent": "TP-Link Scrapper",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
    }


@dataclass
class HostId:
    def __init__(self, ipaddr: str, host: str) -> None:
        self.ipaddr = ipaddr
        self.host = host


@dataclass
class NetInfo:
    def __init__(self) -> None:
        self.wlan24Gcfg = {}
        self.wlan24Gsec = {}
        self.wlan24Gadv = {}
        self.wlan24Gcli: list[Device] = []

        self.wlan50Gcfg = {}
        self.wlan50Gsec = {}
        self.wlan50Gadv = {}
        self.wlan50Gcli: list[Device] = []

        self.guest24Gcfg = {}
        self.guest50Gcfg = {}

        self.ipv4 = {}
        self.routing = {}
        self.fwd_static = {}
        self.fwd_pnp = {}
        self.dhcp_cfg = {}
        self.security = {}


class muParser(HTMLParser):
    def __init__(self, tag, convert_charrefs: bool = True):
        super().__init__(convert_charrefs=convert_charrefs)

        self.tag = tag
        self.data: list = []
        self.cTag = ""
        self.cIdx = 0
        self.cBlock = ""

    def handle_starttag(self, tag, attrs):
        if tag == self.tag:
            self.cBlock = ""
            self.cTag = tag

    def handle_endtag(self, tag):
        if tag == self.tag:
            self.data.append(self.cBlock.strip("\r\n"))
            self.cIdx += 1
            self.cBlock = ""
            self.cTag = ""

    def handle_data(self, data):
        if self.cTag == self.tag:
            self.cBlock += data


class WDRRequest:
    host = ""
    credentials = ""
    timeout = 10
    _logged = False
    _verify_ssl = False
    _logger = None
    _headers_request = {}

    def buildUrl(self, section: str):
        return "{}/userRpm{}".format(self.host, dataUrls[section])

    def request(
        self,
        section: str,
        data: str,
        ignore_response: bool = False,
        ignore_errors: bool = False,
    ) -> str | dict | None:
        if not self._headers_request:
            self._headers_request = defaultHeaders()

        # add xtra headers: User-Agent, Authorization and Referer
        self._headers_request["Referer"] = self.buildUrl("defReferer")
        self._headers_request["User-Agent"] = "TP-Link Scrapper"
        self._headers_request["Authorization"] = "Basic {}".format(self.credentials)

        path = dataUrls[section]
        url = self.buildUrl(section)
        if section == "reboot":
            url = url + "?Reboot=Reboot"

        # Always GET, so data always is a query
        if data:
            url = url + f"?{data}"

        response = get(
            url,
            headers=self._headers_request,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        data = response.content  # better than .text  for later parsing
        if response.ok:
            if ignore_response:
                return None
            if section == "check":
                return response

            return data
        else:
            if ignore_errors:
                return data
            error = ""
            error = (
                (
                    "WDRRouter - {} - Response with error; Request {} - Response {}".format(
                        self.__class__.__name__, path, data
                    )
                )
                if not error
                else error
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientError(error)


class TplinkWDRRouter(AbstractRouter, WDRRequest):
    # _smart_network = True
    _perf_status = False

    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        logger: Logger = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self.credentials = base64.b64encode(
            bytes(f"{self.username}:{self.password}", "utf8")
        ).decode("utf8")
        # device data
        self.status: Status = Status()  # {}
        self.brand = "TP-Link"
        self.firmware: Firmware = {}
        self.hostname = ""
        self.ipv4status: IPv4Status = IPv4Status()
        self.network: NetInfo = NetInfo()
        self.ipv4Reserves: list[IPv4Reservation] = []
        self.dhcpLeases: list[IPv4DHCPLease] = []
        self.connDevices: list[Device] = []

    # N/A. WDR family has no session support , so no "logged" state
    def authorize(self) -> None:
        pass

    def logout(self) -> None:
        pass

    def supports(self) -> bool:
        try:
            response: Response = self.request("check", "")
            return response.status_code == 200
        except Exception:
            return False

    def get_firmware(self) -> Firmware:
        self._updateStatus()
        return self.firmware

    def get_status(self) -> Status:
        self._updateStatus()
        return self.status

    def get_ipv4_status(self) -> IPv4Status:
        self._updateStatus()
        self._updateNet()
        return self.ipv4status

    def get_ipv4_reservations(self):
        self._updateNet()
        return self.ipv4Reserves

    def get_ipv4_dhcp_leases(self):
        self._updateNet()
        return self.dhcpLeases

    def get_clients(self):
        self._updateNet()
        return self.connDevices

    def reboot(self) -> None:
        self.request("reboot", "Reboot=Reboot", True)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        # main wifi cannot be activated / deactivated via software. Only by the phisical button
        # Guest wifi can, but saved changes won't activate until next reboot
        if wifi == Connection.GUEST_2G:
            section = "wgsettings"
            query = "setNetworkMode=1"
        if wifi == Connection.GUEST_2G:
            section = "wgsettings"
            query = "setNetworkMode_5G=1"

        self.request(section, query, True)

    def update(self, what: str = "") -> None:
        if what == "":
            return None
        if what.lower() == "status":
            return self._updateStatus()
        if what.lower() == "firmware":
            return self._updateStatus()
        if what.lower() == "net":
            return self._updateNet()
        if what.lower() == "all":
            self._updateStatus()
            self._updateNet()
            return None

    def _updateStatus(self) -> None:
        raw = self.request("summary", "")
        self._parseSummary(raw)
        self._updateNet()

    def _updateNet(self) -> None:
        sections = "netWan,netLan,dualBand,"
        sections += "w24settings,w24wps,w24sec,w24adv,"
        sections += "w50settings,w50wps,w50sec,w50adv,"
        sections += "wgsettings,wgshare,dhcpconfig,dhcplease,"
        sections += "sysroute,upnpFwd"

        section_list = sections.split(",")
        for section in section_list:
            self._updateSection(section)

        multiPage_list = "w24stations,w50stations,dhcpreserve,portFwd".split(",")
        for section in multiPage_list:
            self._updateMultiSection(section)

        self._updateDevices()

    def _updateDevices(self):
        isWireless: list = []
        w24s: list = self.network.wlan24Gcli

        self.connDevices = []
        for wl24 in w24s:
            if wl24[0] not in isWireless:
                _dev: HostId = self._findHostInLeases(wl24[0])
                thisone = Device(Connection.HOST_2G, wl24[0], _dev.ipaddr, _dev.host)
                thisone.packets_received = wl24[3]
                thisone.packets_sent = wl24[2]
                self.connDevices.append(thisone)
                isWireless.append(wl24[0])

        w50s = self.network.wlan50Gcli
        for wl50 in w50s:
            if wl50[0] not in isWireless:
                _dev: HostId = self._findHostInLeases(wl50[0])
                thisone = Device(Connection.HOST_5G, wl50[0], _dev.ipaddr, _dev.host)
                thisone.packets_received = wl50[3]
                thisone.packets_sent = wl50[2]
                self.connDevices.append(thisone)
                isWireless.append(wl50[0])

        self.status.wifi_clients_total = len(isWireless)

        connected: list[IPv4DHCPLease] = self.dhcpLeases
        client: IPv4DHCPLease = {}

        wired_speed = 1 * 1024 * 1024 * 1024

        for client in connected:
            if client.macaddr not in isWireless:
                thisone = Device(
                    Connection.WIRED, client.macaddr, client.ipaddr, client.hostname
                )
                thisone.up_speed = wired_speed
                thisone.down_speed = wired_speed
                self.connDevices.append(thisone)

        self.status.devices = self.connDevices

        wifiCli = len(isWireless)
        totalCli = len(self.connDevices)
        wiredCli = totalCli - wifiCli

        self.status.wifi_clients_total = wifiCli
        self.status.guest_clients_total = 0
        self.status.clients_total = totalCli
        self.status.wired_total = wiredCli

    def _updateSection(self, section: str) -> None:
        raw = self.request(section, "")
        data = self._parseRawHTML(raw)
        self._parseSection(section, data)

    def _updateMultiSection(self, section: str) -> None:
        # For sections with potentially more than one page
        if section == "w24stations" or section == "w50stations":
            raw = self.request(section, "")
            data = self._parseRawHTML(raw)
            mainData = data["script0"]
            listData: list = data["script1"]
            numTotal = mainData[0] - (mainData[1] - 1) * mainData[2]

            nextPage = False
            if numTotal > mainData[2]:
                numTotal = mainData[2]
                nextPage = True

            while nextPage:
                query = "Page=+int(mainData[1]+1"
                raw = self.request(section, query)
                nextPage = False
                data = self._parseRawHTML(raw)
                mainData = data["script0"]
                listData.extend(data["script1"])
                numTotal = mainData[0] - (mainData[1] - 1) * mainData[2]
                if numTotal > mainData[2]:
                    numTotal = mainData[2]
                    nextPage = True

            self._parseSection(section, {"script0": mainData, "script1": listData})

        elif section == "dhcpreserve":
            raw = self.request(section, "")
            data = self._parseRawHTML(raw)
            currpage = int(data["script1"][0])
            lastpage = int(data["script1"][3])
            tmpData = {}
            while currpage < lastpage:
                query = f"Page={str(currpage + 1)}"
                raw = self.request(section, query)
                tmpData = self._parseRawHTML(raw)

                tArr = tmpData["script0"]
                for item in tArr:
                    data["script0"].append(item)

                currpage = int(tmpData["script1"][0])
                lastpage = int(tmpData["script1"][3])
                data["script1"] = tmpData["script1"]

            self._parseSection(section, data)

        elif section == "portFwd":
            # TODO
            # self._parseSection(section, data)
            pass

    def _parseSection(self, section: str, data: dict) -> None:

        if section == "netLan":
            lanData = data["script0"]
            self.ipv4status._lan_ipv4_netmask = IPv4Address(lanData[3])
            self.network.ipv4["igmpProxy"] = lanData[4]
            self.ipv4status.lan_ipv4_dhcp_enable = False

        elif section == "netWan":
            wanData = data["script1"]
            connType = self._get_conn_type(int(wanData[0]) - 1)
            if not connType:
                connType = "unkown"
            self.ipv4status._wan_ipv4_conntype = connType
            self.status.conn_type = connType

            self.ipv4status._wan_ipv4_netmask = IPv4Address(wanData[14] or "0.0.0.0")
            dns = ["0.0.0.0", "0.0.0.0"]
            # self.ipv4status._wan_ipv4_pridns = '0.0.0.0'
            # self.ipv4status._wan_ipv4_snddns = '0.0.0.0'
            if wanData[19] == "1":
                dns[0] = wanData[20]
                dns[1] = wanData[22]

            self.ipv4status._wan_ipv4_pridns = IPv4Address(dns[0])
            self.ipv4status._wan_ipv4_snddns = IPv4Address(dns[1])

            self.hostname = wanData[26]

        elif section == "dualBand":
            # TODO
            pass
        elif section == "w24settings" or section == "w50settings":
            # TODO
            pass
        elif section == "w24sec" or section == "w50sec":
            # TODO
            pass
        elif section == "w24adv" or section == "w50adv":
            # TODO
            pass
        elif section == "w24stations" or section == "w50stations":
            listData = data["script1"]
            if len(listData) > 3:
                for i in range(0, len(listData), 4):
                    tmpcli = [
                        listData[i],
                        int(listData[i + 1]),
                        int(listData[i + 2]),
                        int(listData[i + 3]),
                    ]
                    if section == "w24stations":
                        self.network.wlan24Gcli.append(tmpcli)
                    elif section == "w50stations":
                        self.network.wlan50Gcli.append(tmpcli)
        elif section == "wgsettings":
            guestData = data["script3"]
            self.status.guest_2g_enable = bool(int(guestData[2]))
            self.status.guest_5g_enable = bool(int(guestData[3]))

        elif section == "wgshare":
            # TODO
            pass
        elif section == "sysroute":
            # TODO
            pass
        elif section == "portFwd":
            # TODO
            pass
        elif section == "upnpFwd":
            # TODO
            pass
        elif section == "dhcpconfig":
            cfg = data["script0"]
            if cfg[0] == 1:
                self.ipv4status.lan_ipv4_dhcp_enable = True
            oCfg = {}
            oCfg["enabled"] = bool(int(cfg[0]))
            oCfg["range_start"] = cfg[1]
            oCfg["range_end"] = cfg[2]
            oCfg["lease_time"] = int(cfg[3])
            oCfg["gateway"] = cfg[4]
            oCfg["domain"] = cfg[5] or None
            oCfg["dns_pri"] = cfg[6] or None
            oCfg["dns_sec"] = cfg[7] or None
            self.network.dhcp_cfg = oCfg
        elif section == "dhcpreserve":
            item: IPv4Reservation = {}
            self.ipv4Reserves = []
            for i in range(0, len(data["script0"]), 3):
                _dev: HostId = self._findHostInLeases(data["script0"][i])
                item = IPv4Reservation(
                    data["script0"][i],
                    data["script0"][i + 1],
                    _dev.host,
                    bool(int(data["script0"][i + 2])),
                )
                self.ipv4Reserves.append(item)
        elif section == "dhcplease":
            self.dhcpLeases = []
            for i in range(0, len(data["script0"]), 4):
                item = IPv4DHCPLease(
                    EUI48(data["script0"][i + 1]),
                    IPv4Address(data["script0"][i + 2]),
                    data["script0"][i],
                    data["script0"][i + 3],
                )
                self.dhcpLeases.append(item)
        elif section == "portFwd":
            # TODO
            pass

    def _parseSummary(self, raw: str) -> None:
        data = self._parseRawHTML(raw)
        tFirm = data["script0"][6]
        tHard = data["script0"][7]
        # WDR3600 v1 00000000
        tModel = tHard.split(" ")
        self.firmware = Firmware(tHard, tModel[0], tFirm)
        self.status = Status()
        self.status.wan_ipv4_uptime = int(data["script0"][8])
        self.status._lan_ipv4_addr = get_ip(data["script1"][1])
        self.status._lan_macaddr = EUI48(data["script1"][0])

        self.ipv4status._lan_ipv4_ipaddr = get_ip(data["script1"][1])
        self.ipv4status._lan_macaddr = EUI48(data["script1"][0])

        self.status._wan_macaddr = EUI48(data["script5"][1])
        self.status._wan_ipv4_addr = get_ip(data["script5"][2])
        self.status._wan_ipv4_gateway = get_ip(data["script5"][7])

        self.ipv4status._wan_macaddr = EUI48(data["script5"][1])
        self.ipv4status._wan_ipv4_ipaddr = get_ip(data["script5"][2])
        self.ipv4status._wan_ipv4_netmask = ""
        self.ipv4status._wan_ipv4_gateway = get_ip(data["script5"][7])

        self.status.guest_2g_enable = None
        self.status.guest_5g_enable = None
        self.status.wifi_2g_enable = bool(int(data["script2"][0]))
        self.status.wifi_5g_enable = bool(int(data["script3"][0]))

        self.status.conn_type = "unknown"
        self.status.devices = []

    def _get_conn_type(self, n: int) -> str:
        wantypeinfo = [
            6,
            0,
            "WanDynamicIpCfgRpm.htm",
            1,
            "WanStaticIpCfgRpm.htm",
            2,
            "PPPoECfgRpm.htm",
            5,
            "BPACfgRpm.htm",
            6,
            "L2TPCfgRpm.htm",
            7,
            "PPTPCfgRpm.htm",
            0,
            0,
        ]
        wantype_filtered = wantypeinfo[2 * n + 1]

        wan_type: list = [
            "Dynamic IP",
            "Static IP",
            "PPPoE/Russia PPPoE",
            "802.1x DHCP",
            "802.1x Static IP",
            "BigPond Cable",
            "L2TP/Russia L2TP",
            "PPTP/Russia PPTP",
        ]
        return wan_type[wantype_filtered]

    def _findHostInLeases(self, macaddr: str) -> HostId:
        arr = self.dhcpLeases
        for lease in arr:
            if lease.macaddr == macaddr:
                return HostId(lease.ipaddr, lease.hostname)

        return HostId("0.0.0.0", "-")

    def _parseRawHTML(self, rawHTML: str) -> dict:

        parser = muParser("script")
        if not rawHTML:
            return {}
        parser.feed(rawHTML.decode("utf8", "ignore"))

        all_scripts = parser.data
        data = {}
        count = 0
        for script in all_scripts:

            if script == "":
                continue

            if not str(script).startswith(("var")):
                continue

            oneLiner = self._parseDataBlock(script)

            newArr = []
            for item in oneLiner.split(","):
                newVal = None
                try:
                    newVal = int(item)
                except Exception:
                    try:
                        newVal = float(item)
                    except Exception:
                        newVal = item
                newArr.append(newVal)

            data["script" + str(count)] = newArr
            count += 1

        return data

    def _parseDataBlock(self, text) -> str:
        lines = text.splitlines()
        if len(lines) < 1:
            return []
        if lines[0] == "":
            lines.pop(0)  # delete first line if empty
        if lines[-1] == "":
            lines.pop()  # delete last line if empty
        lines.pop(0)
        lines.pop()
        result: str = ""
        if len(lines) == 1:
            result = lines[0].replace(", ", ",").replace('"', "")
        else:
            linesNew = []
            for oneLine in lines:
                oneLine = oneLine.replace(", ", ",").replace('"', "")
                linesNew.append(oneLine)
            lines = linesNew
            result = "".join(lines)

        if result.endswith(","):
            result = result[:-1]
        return result
