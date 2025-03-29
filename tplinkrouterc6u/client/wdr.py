import base64
from requests.packages import urllib3
from requests import post, get, Response
from logging import Logger
from macaddress import EUI48
from tplinkrouterc6u.common.helper import get_ip, get_mac
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Firmware, Status, IPv4Status
from tplinkrouterc6u.common.exception import ClientException, ClientError
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device, IPv4Reservation, IPv4DHCPLease, IPv4Status
from tplinkrouterc6u.client_abstract import AbstractRouter

from dataclasses import dataclass
from html.parser import HTMLParser
# from bs4 import BeautifulSoup

dataUrls = {
  'check':"/StatusRpm.htm" ,  
  'summary':"/StatusRpm.htm" ,
  'netWan':"/WanDynamicIpCfgRpm.htm?wan=0",
  'netLan':"/NetworkCfgRpm.htm",
  ## 'macClone': "",
  ## WIFI
  'dualBand':"/WlanBandRpm.htm",
  ## 2.4 Ghz"
  'w24settings':"/WlanNetworkRpm.htm",
  'w24wps':"/WpsCfgRpm.htm", 
  'w24sec':"/WlanSecurityRpm.htm",
  'w24macflt':"/WlanMacFilterRpm.htm",
  'w24adv':"/WlanAdvRpm.htm",
  'w24stations':"/WlanStationRpm.htm?Page=1",
  ## 5.0 Ghz
  'w50settings':"/WlanNetworkRpm_5g.htm",
  'w50wps':"/WpsCfgRpm_5g.htm", 
  'w50sec':"/WlanSecurityRpm_5g.htm",
  'w50macflt':"/WlanMacFilterRpm_5g.htm",
  'w50adv':"/WlanAdvRpm_5g.htm",
  'w50stations':"/WlanStationRpm_5g.htm?Page=1",
  ## Guest Network
  'wgsettings':"/GuestNetWirelessCfgRpm.htm",
  'wgshare':"/GuestNetUsbCfgRpm.htm",
  ## DHCP
  'dhcpconfig':"/LanDhcpServerRpm.htm",
  'dhcplease':"/AssignedIpAddrListRpm.htm",
  'dhcpreserve':"/FixMapCfgRpm.htm",
  ## Referer
  'defReferer':"/MenuRpm.htm",
  ## routing
  'sysroute':"/SysRouteTableRpm.htm",
  'forwarding':"/VirtualServerRpm.htm",
  'upnpFwd':"/UpnpCfgRpm.htm",
  ## Reboot
  'reboot': "/SysRebootHelpRpm.htm"
}




def defaultHeaders():
    return  { # default headers for all requests
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'User-Agent': 'TP-Link Scrapper',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
    }

@dataclass
class HostId:
    def __init__(self,  ipaddr: str, host: str) -> None:
        self.ipaddr =ipaddr
        self.host = host

@dataclass
class NetInfo:
   def __init__(self) -> None: 
        self.wlan24Gcfg = {}
        self.wlan24Gsec = {}
        self.wlan24Gadv = {}
        self.wlan24Gcli:list[Device] = []
        
        self.wlan50Gcfg = {}
        self.wlan50Gsec = {}
        self.wlan50Gadv = {}
        self.wlan50Gcli:list[Device] = []

        self.guest24Gcfg = {}
        self.guest50Gcfg = {}
        
        self.ipv4 = {}
        self.routing = {}
        self.fwd_static = {}
        self.fwd_pnp = {}

        self.security = {}

class muParser(HTMLParser):
    def __init__(self, tag, convert_charrefs = True):
        super().__init__(convert_charrefs=convert_charrefs)

        self.tag= tag
        self.data : list = []
        self.cTag= ""
        self.cIdx = 0 
        self.cBlock = ""

    def handle_starttag(self, tag, attrs):
        if (tag == self.tag):
            self.cBlock = ""
            self.cTag = tag

    def handle_endtag(self, tag):
        if (tag == self.tag):
            self.data.append(self.cBlock.strip('\r\n')) 
            self.cIdx += 1
            self.cBlock = ""
            self.cTag = ""
        
    def handle_data(self, data):
        if (self.cTag == self.tag):
            self.cBlock += data


class WDRRequest:
    host = ''
    credentials = ''
    _stok = ''
    timeout = 10
    _logged = False
    _sysauth = None
    _verify_ssl = False
    _logger = None
    _headers_request = {}
    _headers_login = {}
    _data_block = 'data'

    def buildUrl(self,section:str):
        return '{}/userRpm{}'.format(self.host, dataUrls[section])
    
    def request(self, section: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> str | None:

        if not self._headers_request:
            self._headers_request = defaultHeaders()
        
        ## add xtra headers: User-Agent, Authorization and Referer

        self._headers_request['Referer'] = self.buildUrl("defReferer")
        self._headers_request['User-Agent'] = 'TP-Link Scrapper'
        self._headers_request['Authorization'] = 'Basic {}'.format(self.credentials)
        
        path = dataUrls[section]
        url = self.buildUrl(section)
        if section == "reboot":
            url = url+'?Reboot=Reboot'

        # if section == "dhcpreserve":
        #     print(f'_request GET {url}')
        #     print(f'_request headers {self._headers_request}')
        response = get(     # post(
            url,
            data=self._prepare_data(data),
            headers = self._headers_request,
            timeout = self.timeout,
            verify = self._verify_ssl,
        )

        data = response.content   #better than .text  for later parsing
        if response.ok:
            if ignore_response:
                 return None
            if section == 'check':
                return response
          
            return data
        else:
            if ignore_errors:
                return data

            error = ''

            error = ('WDRRouter - {} - Response with error; Request {} - Response {}'
            .format(self.__class__.__name__, path, data)) if not error else error
            if self._logger:
                self._logger.debug(error)

            raise ClientError

    # def _is_valid_response(self, data: str) -> bool:
    #     #return 'success' in data and data['success'] and self._data_block in data
    #     return True

    def _prepare_data(self, data: str):
        return data

    def _decode_response(self, data: str) -> dict:
        return data

class TplinkWDRRouter(AbstractRouter, WDRRequest):
    #_smart_network = True
    _perf_status = False

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        self.credentials = base64.b64encode(bytes(f'{self.username}:{self.password}','utf8')).decode('utf8')

        # device data
        self.status: Status = {}
        self.firmware: Firmware = {}
        self.ipv4status: IPv4Status = {}
        self.network : NetInfo = {}
        self.ipv4Reserves: list [IPv4Reservation] = []
        self.dhcpLeases: list [IPv4DHCPLease] = []
        self.connDevices: list [Device] = []
        self.pending = {
            "status":  True, 
            "network" : True, 
            "devices": True
            }

   
    # N/A. WDR family has no session support , so no "logged" state
    def authorize(self) -> None:
        pass
    
    def logout(self) -> None:
        pass

    def supports(self) -> bool:
        ## check a simple request where the router identifies itself
        response :Response = self.request("check", '')
        return response.status_code == 200 and "WDR" in response.headers["www-authenticate"]

    def get_firmware(self) -> Firmware:
        if self.pending['status'] == True:
            self._updateStatus()
        return self.firmware

    def get_status(self) -> Status:
        if self.pending['status'] == True:
            self._updateStatus()
        return self.status
 
    def get_ipv4_status(self) -> IPv4Status:
        if self.pending['network'] == True:
            self._updateNet()
        return self.network.ipv4
    
    def get_ipv4_reservations(self):
        if self.pending['network'] == True:
            self._updateNet()
        return self.ipv4Reserves        

    def get_ipv4_dhcp_leases(self):
        if self.pending['network'] == True:
            self._updateNet()
        return self.dhcpLeases        

    def get_clients(self):
        if self.pending['network'] == True:
            self._updateNet()
        return self.status.devices
        

    def reboot(self) -> None:
        self.request('reboot', 'Reboot=Reboot', True)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        # main wifi cannot be activated /deactivvated via software. ONly by the phisical button
        # Saved changes won't activate until next reboot
        return None
        if wifi == Connection.GUEST_2G:
            section = "wgsettings"
            query ='setNetworkMode=1'
        if wifi == Connection.GUEST_2G:
            section = "wgsettings"
            query ='setNetworkMode_5G=1'

        self.request(section, query, True)
        
    def update(self, what: str = "") -> None:
        if what == "":
            return None
        if what.lower() == 'status': return self._updateStatus()
        if what.lower() == 'firmware': return self._updateStatus()
        if what.lower() == 'net': return self._updateNet()
        if what.lower() == "all": 
            self._updateStatus()
            self._updateNet()
            return None
    
    def _updateStatus(self) -> None:
        raw = self.request("summary", "")
        self._parseSummary(raw)   
        self.pending['status'] == False

    def _updateNet(self) -> None:
        sections = "netWan,netLan,dualBand,"
        sections += "w24settings,w24wps,w24sec,w24adv,"
        sections += "w50settings,w50wps,w50sec,w50adv,"
        sections += "wgsettings,wgshare,dhcpconfig,dhcplease,"
        sections += "sysroute,upnpFwd"
        section_list = sections.split(',')
        raw:str =''
        for section in section_list: self._updateSection(section)
            # raw = self.request(section, "")
            # self._parseSection(section,raw)
        
        multiPage_list = "w24stations,w50stations,dhcpreserve,forwarding".split(",")

        for section in multiPage_list: self._updateMultiSection(section)
        
        self._updateDevices()
        self.pending['network'] == False 

    def _updateDevices(self):
        # get the wLan clients
        # get DHCP leases
        # Build wired client list by diff DHCP Leases with Wlan clients list
   
        isWireless: list = []
        
        print ("_UD:0", self.network)
        w24s:list = self.network.wlan24Gcli
        
        for wl24 in w24s:
            _dev : HostId = self._findHostInLeases(wl24[0])
            aDev = [
                Connection.HOST_2G, 
                wl24[0],_dev.ipaddr ,_dev.host,
                wl24[3], wl24[2],
                None,None,None
                ]
            thisone= Device(aDev[0], aDev[1], aDev[2], aDev[3], aDev[4], aDev[5], None, None, None) 
            self.connDevices.append(thisone)
            isWireless.append(aDev[1])

        w50s = self.network.wlan50Gcli
        for wl50 in w50s:
            _dev : HostId = self._findHostInLeases(wl50[0])
            aDev = [
                Connection.HOST_5G, 
                wl50[0],_dev.ipaddr ,_dev.host,
                wl50[3], wl50[2],
                None,None,None
                ]
            thisone= Device(aDev[0], aDev[1], aDev[2], aDev[3], aDev[4], aDev[5], None, None, None) 
            self.connDevices.append(thisone)
            
        self.status.wifi_clients_total = len(isWireless)

        connected: list[IPv4DHCPLease]  = self.dhcpLeases
        client: IPv4DHCPLease

        wired_speed = 1*1024*1024*1024

        for client in connected:
            if not client.macaddr in isWireless:
                thisone= Device(Connection.WIRED, client.macaddr, client.ipaddr, client.hostname, None, None, wired_speed, wired_speed, None)
                self.connDevices.append(thisone) 

        self.pending['devices'] = False


    def _updateSection(self,section:str) -> None:
        raw = self.request(section, "")
        data = self._parseRawHTML(raw)
        self._parseSection(section,data) 

    def _updateMultiSection(self,section:str) -> None:
        # print(f'_uMP.0 {section}')
        if section == "w24stations":
            pass
        elif section == "w50stations":        
            pass
        elif section == "dhcpreserve":
            # var dhcpList = new Array("30-5A-3A-7F-5E-CC", "192.168.1.16", 1, "40-E2-30-42-08-4F", "192.168.1.71", 1, ...0,0 );
            # var DHCPStaticPara = new Array(1,1,8,3,8,0,0 );
            # var DHCPStaticPara = new Array(2,1,8,3,8,0,0 );
            # var DHCPStaticPara = new Array(3,0,3,3,8,0,0 );
            raw = self.request(section, "")
            data = self._parseRawHTML(raw)
            currpage = int(data['script1'][0])
            lastpage = int(data['script1'][0])
            tmpData = {}
            while currpage < lastpage:
                query=f'Page={str(currPage + 1)}'
                raw = self.request( section, query) 

                tmpData = self._parseRawHTML(raw)  
                tArr=tmpData['script0']
                for item in tArr:
                    data['script0'].append(item)
                #tmpData["script00"].map(e => data["script00"].push(e))

                currPage=int(tmpData['script1'][0])  

            item : IPv4Reservation = {}   
            for i in range(0,len(data['script0']), 3):
                _dev: HostId = self._findHostInLeases(data['script0'][i])
                item = IPv4Reservation(
                    data['script0'][i],
                    data['script0'][i+1],
                    _dev.host,
                    bool(int(data['script0'][i+2]))
                    )
                # print( "RES", data['script0'][i], data['script0'][i+1], data['script0'][i+2])
                self.ipv4Reserves.append(item)
        elif section == "forwarding":
            pass 
        
    def _parseSummary(self, raw:str) -> None:
        data = self._parseRawHTML(raw)
        # print (f'_pS.0 {data}')
        tFirm= data['script0'][6]
        tHard = data['script0'][7]
        ## WDR3600 v1 00000000
        tModel = tHard.split(" ")
        self.firmware= Firmware(tHard, tModel, tFirm)
        self.status = Status()
        self.status.wan_ipv4_uptime = int(data['script0'][8]) 
        self.status._lan_ipv4addr = get_ip(data['script1'][1])
        self.status._lan_macaddr = EUI48(data['script1'][0])

        # 0 var statusPara = new Array(1,1,1,22,20000,2493718,"3.13.34 Build 130909 Rel.53148n ","WDR3600 v1 00000000",6732336,0,0 );
        # 1 var lanPara = new Array("C4-6E-1F-41-67-C0", "192.168.1.254", "255.255.255.0", 0,0 );
        # 2 var wlanPara = new Array(1,"hermes24",15,5,"C4-6E-1F-41-67-BF","192.168.1.254",2,8,71,11,6,0,0 );
        # 3 var wlan5GPara = new Array(1,"hermes",15,8,"C4-6E-1F-41-67-C0","192.168.1.254",2,8,83,36,6,0,0 );
        # 4 var statistList = new Array( 1903689570, 1044405559, 141728548, 127489568, 0,0 );
        # 5 var wanPara = new Array(4, "C4-6E-1F-41-67-C1", "192.168.0.129", 1, "255.255.255.0", 0, 0, "192.168.0.1", 1, 1, 0, "212.230.135.2 , 212.142.173.65", "", 0, 0, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0 , 0.0.0.0", 0, 0, 0, 0, 0,  0,0 );
        
        self.status._wan_macaddr = EUI48(data['script5'][1])
        self.status._wan_ipv4_addr = get_ip(data['script5'][2])
        self.status._wan_ipv4_gateway = get_ip(data['script5'][7])
        self.status.guest_2g_enable = None
        self.status.guest_5g_enable =  None
        self.status.wifi_2g_enable = bool(int(data['script2'][0]))
        self.status.wifi_5g_enable =  bool(int(data['script3'][0]))
        self.status.conn_type = self._get_conn_type(int(data['script5'][0]))
        self.status.devices = []
        # status = {
        #     '_wan_macaddr': None, # EUI48 | None = None
        #     '_lan_macaddr': None ,  # EUI48
        #     '_wan_ipv4_addr': None, # IPv4Address | None = None
        #     '_lan_ipv4_addr': None, # IPv4Address | None = None
        #     '_wan_ipv4_gateway': None, # IPv4Address | None = None
        #     'wired_total': 0,
        #     'wifi_clients_total': 0,
        #     'guest_clients_total': 0,
        #     'clients_total':  0,
        #     'guest_2g_enable': None,
        #     'guest_5g_enable': None,
        #     'wifi_2g_enable': None,
        #     'wifi_5g_enable': None,
        #     'wan_ipv4_uptime': 0, # int | None = None,
        #     'mem_usage': None,
        #     'cpu_usage': None,
        #     'conn_type': "",
        #     'devices': list[Device] = []
        # }

    def _get_conn_type(self,n:int) ->str:
        transform = [0,1,2,5,6,7]
        idx = transform[n]
        wan_type: list = [
            'Dynamic IP',
            'Static IP',
            'PPPoE/Russia PPPoE',
            '802.1x DHCP',
            '802.1x Static IP',
            'BigPond Cable',
            'L2TP/Russia L2TP',
            'PPTP/Russia PPTP',
        ]
        return wan_type[idx]

    def _parseSection(self, section:str, data:dict) -> None:
        if section == "netLan":
            pass
        elif section == "netWan":
            pass
        elif section == "dhcplease":
            for i in range(0,len(data['script0']), 4):
                item = IPv4DHCPLease(
                    data['script0'][i+1],
                    data['script0'][i+2],
                    data['script0'][i],
                    data['script0'][i+3]
                    )
                # print( "LEASE", data['script0'][i+1], data['script0'][i+2], data['script0'][i],data['script0'][i+3])
                self.dhcpLeases.append(item)

    def _parseRawHTML(self, rawHTML:str) -> dict:
        parser = muParser('script')
        parser.feed(rawHTML.decode('utf8', 'ignore'))

        all_scripts = parser.data
        # print ("_pRH.0", len(all_scripts), parser.cIdx)
        data = {}
        count=0
        #all_scripts = result('script')
        ## scripts seem to be there onely to write each one an array of params ikn form of 
        ##
        ## var someName  = [
        ## "a", "lot", "of", "values", 0, 1, 2, 3, 4, 5, 6
        ## 0,0]
        for script in all_scripts:
            
            if script == "" :
                continue
            
            # script=str(script).strip('\r\n')
            # print (f'_pRH.1 {script[0:3]}')

            if not str(script).startswith(('var')) :
                continue

            # print (f'_pRH.2 {script}')

            oneLiner = self._parseDataBlock(script)
            
            # print ("_pRH.2",oneLiner)
            newArr = []
            for item in oneLiner.split(","):
                newVal = None
                try:
                    newVal = int(item)
                except Exception as e:
                    try:
                        newVal = float(item)
                    except Exception as e:
                        newVal = item
                newArr.append(newVal)

            data["script"+str(count)] = newArr        
            count += 1

        return data


    # def _parseSoupHTML(self, data:str) -> dict:
    #     result = BeautifulSoup(data, "html.parser")
    #     data = {}
    #     count=0
    #     all_scripts = result('script')
    #     ## scripts seem to be there onely to write each one an array of params ikn form of 
    #     ##
    #     ## var someName  = [
    #     ## "a", "lot", "of", "values", 0, 1, 2, 3, 4, 5, 6
    #     ## 0,0]
    #     for script in all_scripts:
    #         temptxt = script.text
    #         lines = temptxt.splitlines()
    #         lines.pop(0)   # delete first line
    #         lines.pop()   # delete last line
    #         if (len(lines) == 1):
    #             oneliner = lines[0].replace(", ", ",").replace('"', '')
    #         else:
    #             linesNew= []
    #             for line in lines:
    #                 line = line.replace(", ", ",").replace('"', '')
    #                 linesNew.append(line)    
    #             lines=linesNew
    #             oneliner = "".join(lines) 
                
    #         if oneliner.endswith(","):
    #             oneliner = oneliner[:-1]
    #         # data["script"+str(count)] = oneliner.split(",")
    #         newArr = []
    #         for item in oneliner.split(","):
    #             newVal = None
    #             try:
    #                 newVal = int(item)
    #             except Exception as e:
    #                 try:
    #                     newVal = float(item)
    #                 except Exception as e:
    #                     newVal = item
                
    #             newArr.append(newVal)

    #         data["script"+str(count)] = newArr        
            
    #         count += 1

    #     return data

    def _parseDataBlock(self, text) -> str:
        # print (f'_pDB.0 {text or "empty"}')
        lines = text.splitlines()
        if len(lines) < 1: 
            return []
        # trim empty lines
        if lines[0] == "":  lines.pop(0)   # delete first line
        if lines[-1] == "": lines.pop()   # delete last line
        lines.pop(0)
        lines.pop()
        result: str = ""
        if (len(lines) == 1):
            result = lines[0].replace(", ", ",").replace('"', '')
            # print (f'_pDB.1 {result}')
        else:
            linesNew= []
            for oneLine in lines:
                oneLine = oneLine.replace(", ", ",").replace('"', '')
                linesNew.append(oneLine)    
            lines=linesNew
            result = "".join(lines) 
            # print (f'_pDB.2 {result}')
            
        if result.endswith(","):
            result = result[:-1]    
        return result    

    def _findHostInLeases(self,macaddr:str) -> HostId:
        arr = self.dhcpLeases
        #ret : HostId = HostId('0.0.0.0','-')
        for lease in arr:
            if lease.macaddr == macaddr:
                return HostId(lease.ipaddr, lease.hostname)
                # return {"ip":lease.ipaddr, "hostname":lease.hostname}
                
        return HostId('0.0.0.0','-')