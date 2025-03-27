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
from bs4 import BeautifulSoup

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

        def __buildUrl(section:str):
            return '{}/userRpm/{}'.format(self.host, section)

        if not self._headers_request:
            self._headers_request = defaultHeaders()
        
        ## add xtra headers: User-Agent, Authorization and Referer

        self._headers_request['Referer']: __buildUrl("defReferer") # type: ignore
        self._headers_request['User-Agent'] = 'TP-Link Scrapper'
        self._headers_request['Authorization'] = 'Basic {}'.format(self.credentials)
        
        path = dataUrls[section]
        url = __buildUrl(section)
        if section == "reboot":
            url = url+'?Reboot=Reboot'

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
            return data
        else:
            if ignore_errors:
                return data
            if section == 'check':
                return response
            error = ''

            error = ('WDRRouter - {} - Response with error; Request {} - Response {}'
            .format(self.__class__.__name__, path, data)) if not error else error
            if self._logger:
                self._logger.debug(error)

            raise ClientError

    def _is_valid_response(self, data: str) -> bool:
        #return 'success' in data and data['success'] and self._data_block in data
        return True

    def _prepare_data(self, data: str):
        return data

    def _decode_response(self, data: str) -> dict:
        return data

class TplinkWDRRouter(AbstractRouter, WDRRequest):
    _smart_network = True
    _perf_status = True

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)

        # self.credentials = base64.b64encode('{self.username}:{self.password}')
        self.credentials = base64.b64encode(bytes(f'{self.username}:{self.password}','utf8')).decode('utf8')

        
        ## self._url_firmware = 'admin/firmware?form=upgrade&operation=read'
        # self._url_firmware = dataUrls("dhcpreserves") # 'userRpm/StatusRpm.htm'
        # self._url_ipv4_reservations = dataUrls('dhcpreserves') # 'admin/dhcps?form=reservation&operation=load'
        # self._url_ipv4_dhcp_leases = dataUrls('dhcpreserves') #'admin/dhcps?form=client&operation=load'
        # referer = '{}/webpages/index.html'.format(self.host)
        # self._headers_request = {'Referer': referer}
        # self._headers_login = {'Referer': referer, 'Content-Type': 'application/x-www-form-urlencoded'}

        # device data
        self.status : Status
        self.firmware : Firmware
        self.net : IPv4Status
   

    def authorize(self) -> bool:
        # N/A. WDR family has no session, so no "logged " state
        return True
    
    def logout(self) -> None:
        # N/A. WDR family has no session, so no "logged " state
        pass

    def supports(self) -> bool:
        ## check a simple request tahta demostrates teh router answering ok

        response = self.request("check", '', True)
        return response.status_code == 200 and response.text.startswith('00000')

    def reboot(self) -> None:
        self.request('reboot', '', True)

    def get_firmware(self) -> Firmware:
        return self.firmware

    def get_status(self) -> Status:
        self.status = Status()
        return self.status
 
    def get_ipv4_status(self) -> IPv4Status:
        
        pass

    def reboot(self) -> None:
        pass

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        pass


    def update(self, what: str = "") -> None:
        if what == "":
            return None
        if what.lower() == 'status': return self.updateStatus()
        if what.lower() == 'firmware': return self.updateFirmware()
        if what.lower() == 'net': return self.updatenet()
        if what.lower() == "all": 
            self.updateStatus()
            self.updateFirmware()
            self.updateNet()
            return None
    
    def updateStatus(self) -> Status:
        raw = self.request("summary", "")
        data = self._parseSummary(raw)
        

    def updateFirmware(self) -> Firmware:
        ## nothing to request Firmware info comes from summary
        pass

    def updateNet(self) -> Status:
        sections = "netWan,netLan,dualBand,"
        sections += "w24settings,w24wps,w24sec,w24adv,w24stations,"
        sections += "w50settings,w50wps,w50sec,w50adv,w50stations,"
        sections += "wgsettings,wgshare,dhcpconfig,dhcplease,dhcpreserve,"
        sections += "sysroute,forwarding,upnpFwd"
        section_list = sections.split(',')
        raw:str =''
        for section in section_list:
            raw = self.request(section, "")
            self._parseSection(section,raw)


    def _parseSummary(self, raw:str) -> None:
        data = self._parseRawHTML(raw)
        tFirm= data['script0'][6]
        tHard = data['script0'][7]
        ## WDR3600 v1 00000000
        tModel = tHard.split(" ")
        self.firmware= Firmware(tHard, tModel, tFirm)
        self.status = Status()
        self.status.wan_ipv4_uptime = int(data['script0'][8]) 
        self._lan_ipv4addr = get_ip(data['script1'][1])
        self._lan_macaddr = EUI48(data['script1'][0])
        # var wanPara = new Array(
        # 4, "C4-6E-1F-41-67-C1", "192.168.0.129", 1, "255.255.255.0", 0, 0, "192.168.0.1", 1, 1, 0, "212.230.135.2 , 212.142.173.65", "", 0, 0, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0 , 0.0.0.0", 0, 0, 0, 0, 0, 
        # 0,0 );
        self._wan_macaddr = EUI48(data['script5'][1])
        self._wan_ipv4_addr = get_ip(data['script5'][2])
        self._wan_ipv4_gateway = get_ip(data['script5'][7])

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


    def _parseSection(self, section:str, raw:str) -> None:
        pass



    def _parseRawHTML(self, data:str) -> dict:
        result = BeautifulSoup(data, "html.parser")
        data = {}
        count=0
        all_scripts = result('script')
        ## scripts seem to be there onely to write each one an array of params ikn form of 
        ##
        ## var someName  = [
        ## "a", "lot", "of", "values", 0, 1, 2, 3, 4, 5, 6
        ## 0,0]
        for script in all_scripts:
            temptxt = script.text
            lines = temptxt.splitlines()
            lines.pop(0)   # delete first line
            lines.pop()   # delete last line
            if (len(lines) == 1):
                oneliner = lines[0].replace(", ", ",").replace('"', '')
            else:
                linesNew= []
                for line in lines:
                    line = line.replace(", ", ",").replace('"', '')
                    linesNew.append(line)    
                lines=linesNew
                oneliner = "".join(lines) 
                
            if oneliner.endswith(","):
                oneliner = oneliner[:-1]
            # data["script"+str(count)] = oneliner.split(",")
            newArr = []
            for item in oneliner.split(","):
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

