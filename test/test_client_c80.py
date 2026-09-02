from unittest import main, TestCase
from unittest.mock import patch
from ipaddress import IPv4Address, IPv6Address
from macaddress import EUI48
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device
from tplinkrouterc6u.common.dataclass import IPv4Status, IPv6Status, IPv4Reservation, IPv4DHCPLease, VPNStatus
from tplinkrouterc6u import Connection, ClientException
from tplinkrouterc6u.client.c80 import TplinkC80Router, RouterConstants


IPV4_STATUS_RESPONSE = ('00000\r\nid 1|1,0,0\r\nauthKey token\r\nreserved\r\nsetWzd 8\r\nmode 1\r\nlogLevel 3\r\n'
                        'fastpath 1\r\nmac 0 00-00-00-00-00-00\r\nmac 1 00-00-00-00-00-01\r\nwanMacType 0\r\n'
                        'modelMergeCursor 8\r\nid 4|1,0,0\r\nip 192.168.0.1\r\nmask 255.255.255.0\r\nmode 0\r\n'
                        'smartIp 1\r\ngateway 192.168.0.1\r\nid 8|1,0,0\r\nenable 1\r\npoolStart 192.168.0.100\r\n'
                        'poolEnd 192.168.0.249\r\nleaseTime 120\r\ndns 0 0.0.0.0\r\ndns 1 0.0.0.0\r\ngateway 0.0.0.0'
                        '\r\nhostName\r\nrelayEnableAll 0\r\nrelayEnable 0\r\nrelayServer 0.0.0.0\r\nid 22|1,0,0'
                        '\r\nenable 1\r\nneedPnpDetect 0\r\nocnDetect 0\r\nreserved\r\nlinkMode 0\r\nlinkType 0\r\n'
                        'id 23|1,0,0\r\nip 1.0.1.1\r\nmask 255.255.252.0\r\ngateway 1.0.0.1\r\ndns 0 8.8.8.8\r\n'
                        'dns 1 8.8.8.8\r\nstatus 1\r\ncode 0\r\nupTime 42601\r\ninPkts 12018031\r\ninOctets 1549640652'
                        '\r\noutPkts 31192286\r\noutOctets 182616925\r\ninRates 939\r\noutRates 318\r\ndualMode 0\r\n'
                        'dualIp 0.0.0.0\r\ndualMask 0.0.0.0\r\ndualGateway 0.0.0.0\r\ndualDns 0 0.0.0.0\r\n'
                        'dualDns 1 0.0.0.0\r\ndualCode 1\r\ndualStatus 3\r\ninternetDnsDetect 1\r\nid 24|1,0,0\r\n'
                        'ip 1.0.0.1\r\nmask 255.255.255.0\r\ngateway 1.0.0.1\r\ndns 0 8.8.8.8\r\ndns 1 8.8.8.8\r\n'
                        'mtu 1500')


IPV4_RESPONSE_TEXT = ('00000\r\nid 1|1,0,0\r\nauthKey token\r\nreserved\r\nsetWzd 8\r\nmode 1\r\nlogLevel 3'
                      '\r\nfastpath 1\r\nmac 0 00-00-00-00-00-00\r\nmac 1 00-00-00-00-00-01\r\nwanMacType 0'
                      '\r\nmodelMergeCursor 8\r\nid 4|1,0,0\r\nip 192.168.0.1\r\nmask 255.255.255.0\r\n'
                      'mode 0\r\nsmartIp 1\r\ngateway 192.168.0.1\r\nid 8|1,0,0\r\nenable 1\r\n'
                      'poolStart 192.168.0.100\r\npoolEnd 192.168.0.249\r\nleaseTime 120\r\ndns 0 0.0.0.0'
                      '\r\ndns 1 0.0.0.0\r\ngateway 0.0.0.0\r\nhostName\r\nrelayEnableAll 0\r\n'
                      'relayEnable 0\r\nrelayServer 0.0.0.0\r\nid 22|1,0,0\r\nenable 1\r\nneedPnpDetect 0'
                      '\r\nocnDetect 0\r\nreserved\r\nlinkMode 0\r\nlinkType 0\r\nid 23|1,0,0\r\n'
                      'ip 1.1.1.1\r\nmask 255.255.252.0\r\ngateway 1.1.1.2\r\ndns 0 5.8.8.8\r\n'
                      'dns 1 5.8.8.8\r\nstatus 1\r\ncode 0\r\nupTime 15000\r\ninPkts 9537954\r\n'
                      'inOctets 327534332\r\noutPkts 24449491\r\noutOctets 2189487468\r\ninRates 42346'
                      '\r\noutRates 19222\r\ndualMode 0\r\ndualIp 0.0.0.0\r\ndualMask 0.0.0.0\r\n'
                      'dualGateway 0.0.0.0\r\ndualDns 0 0.0.0.0\r\ndualDns 1 0.0.0.0\r\ndualCode 1'
                      '\r\ndualStatus 3\r\ninternetDnsDetect 1\r\nid 24|1,0,0\r\nip 1.0.0.1\r\n'
                      'mask 255.255.255.0\r\ngateway 1.0.0.1\r\ndns 0 8.8.8.8\r\ndns 1 8.8.8.8\r\nmtu 1500')

STATUS_RESPONSE_TEXT = ('00000\r\nid 1|1,0,0\r\nauthKey aaa3eKKee\r\nreserved\r\nsetWzd 8\r\nmode 1\r\n'
                        'logLevel 3\r\nfastpath 1\r\nmac 0 00-00-00-00-00-00\r\nmac 1 00-00-00-00-00-01'
                        '\r\nwanMacType 0\r\nmodelMergeCursor 8\r\nid 4|1,0,0\r\nip 192.168.0.1\r\n'
                        'mask 255.255.255.0\r\nmode 0\r\nsmartIp 1\r\ngateway 192.168.0.1\r\nid 23|1,0,0'
                        '\r\nip 100.100.100.100\r\nmask 255.255.252.0\r\ngateway 100.100.105.1\r\n'
                        'dns 0 100.100.0.1\r\ndns 1 100.100.0.1\r\nstatus 1\r\ncode 0\r\nupTime 30814980'
                        '\r\ninPkts 3014881\r\ninOctets 1502000045\r\noutPkts 8216676\r\noutOctets 2500478193'
                        '\r\ninRates 337\r\noutRates 714\r\ndualMode 0\r\ndualIp 0.0.0.0\r\ndualMask 0.0.0.0'
                        '\r\ndualGateway 0.0.0.0\r\ndualDns 0 0.0.0.0\r\ndualDns 1 0.0.0.0\r\ndualCode 0'
                        '\r\ndualStatus 0\r\ninternetDnsDetect 1\r\nid 13|1,0,0\r\nip 0 192.168.0.1\r\n'
                        'ip 1 192.168.0.2\r\nip 2 192.168.0.3\r\nip 3 192.168.0.4\r\nip 4 192.168.0.5'
                        '\r\nip 5 192.168.0.6\r\nmac 0 00-00-00-00-00-02\r\nmac 1 00-00-00-00-00-03'
                        '\r\nmac 2 00-00-00-00-00-04\r\nmac 3 00-00-00-00-00-05\r\nmac 4 00-00-00-00-00-06'
                        '\r\nmac 5 00-00-00-00-00-07\r\nbindEntry 0 0\r\nbindEntry 1 0\r\nbindEntry 2 0'
                        '\r\nbindEntry 3 0\r\nbindEntry 4 0\r\nbindEntry 5 0\r\nstaMgtEntry 0 0\r\n'
                        'staMgtEntry 1 0\r\nstaMgtEntry 2 0\r\nstaMgtEntry 3 0\r\nstaMgtEntry 4 1'
                        '\r\nstaMgtEntry 5 0\r\ntype 0 3\r\ntype 1 1\r\ntype 2 2\r\ntype 3 1\r\ntype 4 13'
                        '\r\ntype 5 0\r\nonline 0 0\r\nonline 1 0\r\nonline 2 1\r\nonline 3 1\r\nonline 4 1'
                        '\r\nonline 5 1\r\nblocked 0 0\r\nblocked 1 0\r\nblocked 2 0\r\nblocked 3 0\r\n'
                        'blocked 4 0\r\nblocked 5 0\r\nqosPrior 0 0\r\nqosPrior 1 0\r\nqosPrior 2 0\r\n'
                        'qosPrior 3 0\r\nqosPrior 4 0\r\nqosPrior 5 0\r\nup 0 0\r\nup 1 0\r\nup 2 30\r\n'
                        'up 3 800\r\nup 4 1824\r\nup 5 600\r\ndown 0 0\r\ndown 1 0\r\ndown 2 200\r\n'
                        'down 3 400\r\ndown 4 800\r\ndown 5 50\r\nupLimit 0 204800\r\nupLimit 1 204800\r\n'
                        'upLimit 2 204800\r\nupLimit 3 204800\r\nupLimit 4 204800\r\nupLimit 5 204800\r\n'
                        'downLimit 0 1048576\r\ndownLimit 1 1048576\r\ndownLimit 2 1048576\r\n'
                        'downLimit 3 1048576\r\ndownLimit 4 1048576\r\ndownLimit 5 1048576\r\nname 0 Laptop'
                        '\r\nname 1 iPhone\r\nname 2 Laptop2\r\nname 3 iPhone2\r\nname 4 IoT_thing\r\n'
                        'name 5 PC\r\nuBandwidth 0 0\r\nuBandwidth 1 0\r\nuBandwidth 2 0\r\nuBandwidth 3 0'
                        '\r\nuBandwidth 4 0\r\nuBandwidth 5 0\r\nuStandard 0 0\r\nuStandard 1 0\r\n'
                        'uStandard 2 0\r\nuStandard 3 2\r\nuStandard 4 2\r\nuStandard 5 0\r\ndevType 0 0'
                        '\r\ndevType 1 0\r\ndevType 2 0\r\ndevType 3 0\r\ndevType 4 0\r\ndevType 5 0\r\n'
                        'priTime 0 0\r\npriTime 1 0\r\npriTime 2 0\r\npriTime 3 0\r\npriTime 4 0\r\n'
                        'priTime 5 0\r\nleaseTime 0 0\r\nleaseTime 1 0\r\nleaseTime 2 0\r\nleaseTime 3 0'
                        '\r\nleaseTime 4 0\r\nleaseTime 5 0\r\ntotalVal 0 450\r\ntotalVal 1 5\r\n'
                        'totalVal 2 13\r\ntotalVal 3 956\r\ntotalVal 4 13\r\ntotalVal 5 53\r\ntotalUnit 0 2'
                        '\r\ntotalUnit 1 2\r\ntotalUnit 2 2\r\ntotalUnit 3 2\r\ntotalUnit 4 2\r\n'
                        'totalUnit 5 2\r\ndhcpsEntry 0 0\r\ndhcpsEntry 1 0\r\ndhcpsEntry 2 0\r\n'
                        'dhcpsEntry 3 0\r\ndhcpsEntry 4 0\r\ndhcpsEntry 5 0\r\nduration 0 0\r\n'
                        'duration 1 0\r\nduration 2 0\r\nduration 3 73\r\nduration 4 5388\r\n'
                        'duration 5 8559\r\ntxRate 0 0\r\ntxRate 1 0\r\ntxRate 2 0\r\ntxRate 3 156\r\n'
                        'txRate 4 130\r\ntxRate 5 0\r\nrxRate 0 0\r\nrxRate 1 0\r\nrxRate 2 0\r\n'
                        'rxRate 3 130\r\nrxRate 4 173\r\nrxRate 5 0\r\naveRssi 0 0\r\naveRssi 1 0\r\n'
                        'aveRssi 2 0\r\naveRssi 3 33\r\naveRssi 4 46\r\naveRssi 5 0\r\nslEnable 0 0\r\n'
                        'slEnable 1 0\r\nslEnable 2 0\r\nslEnable 3 0\r\nslEnable 4 0\r\nslEnable 5 0'
                        '\r\npriScheStatus 0 0\r\npriScheStatus 1 0\r\npriScheStatus 2 0\r\n'
                        'priScheStatus 3 0\r\npriScheStatus 4 0\r\npriScheStatus 5 0\r\nstart 0 0\r\n'
                        'start 1 0\r\nstart 2 0\r\nstart 3 0\r\nstart 4 0\r\nstart 5 0\r\nend 0 0\r\n'
                        'end 1 0\r\nend 2 0\r\nend 3 0\r\nend 4 0\r\nend 5 0\r\nday 0 0\r\nday 1 0\r\n'
                        'day 2 0\r\nday 3 0\r\nday 4 0\r\nday 5 0\r\nstartMin 0 0\r\nstartMin 1 0\r\n'
                        'startMin 2 0\r\nstartMin 3 0\r\nstartMin 4 0\r\nstartMin 5 0\r\nendMin 0 0\r\n'
                        'endMin 1 0\r\nendMin 2 0\r\nendMin 3 0\r\nendMin 4 0\r\nendMin 5 0\r\nrate 0 0'
                        '\r\nrate 1 0\r\nrate 2 0\r\nrate 3 156\r\nrate 4 173\r\nrate 5 0\r\ntxPkt 0 0'
                        '\r\ntxPkt 1 0\r\ntxPkt 2 0\r\ntxPkt 3 42602\r\ntxPkt 4 119683\r\ntxPkt 5 0'
                        '\r\nrxPkt 0 0\r\nrxPkt 1 0\r\nrxPkt 2 0\r\nrxPkt 3 6343\r\nrxPkt 4 275076\r\n'
                        'rxPkt 5 0\r\nid 33|1,1,0\r\nuUnit 0\r\ncSsidPrefix\r\nuRadiusIp 0.0.0.0\r\n'
                        'uRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0'
                        '\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\n'
                        'cKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\n'
                        'bBcastSsid 1\r\ncSsid TP-Link\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3'
                        '\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3'
                        '\r\ncRadiusSecret\r\ncPskSecret admin\r\nbSecCheck 0\r\nbEnabled 1\r\n'
                        'cUsrPIN 11100111\r\nbConfigured 1\r\nbIsLocked 0\r\nbEnRtPIN 1\r\n'
                        'bWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1'
                        '\r\nSecurityType 2\r\nbApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1'
                        '\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 1\r\nbTr069APEnable 0'
                        '\r\nbTr069SSIDEnable 0\r\nid 33|2,1,0\r\nuUnit 0\r\ncSsidPrefix\r\nuRadiusIp 0.0.0.0'
                        '\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0'
                        '\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\n'
                        'cKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\n'
                        'bBcastSsid 1\r\ncSsid TP-Link\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3'
                        '\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3'
                        '\r\ncRadiusSecret\r\ncPskSecret admin\r\nbSecCheck 0\r\nbEnabled 1\r\n'
                        'cUsrPIN 11100111\r\nbConfigured 1\r\nbIsLocked 0\r\nbEnRtPIN 1\r\nbWifiBtnRecEnable 1'
                        '\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1\r\nSecurityType 2\r\n'
                        'bApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\n'
                        'bwCtrlEnable 0\r\nenableBackup 1\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\n'
                        'id 33|1,2,0\r\nuUnit 1\r\ncSsidPrefix Guest\r\nuRadiusIp 0.0.0.0\r\n'
                        'uRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0'
                        '\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\n'
                        'cKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 0\r\n'
                        'bBcastSsid 1\r\ncSsid TP-Link_Guest\r\nbSecurityEnable 0\r\nuAuthType 3\r\n'
                        'uWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 3\r\nuRadiusEncryptType 1\r\n'
                        'uPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret\r\nbSecCheck 0\r\nbEnabled 1'
                        '\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0\r\n'
                        'bWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 0'
                        '\r\nSecurityType 1\r\nbApIsolated 1\r\neffectiveTime 0\r\nuMaxUploadSpeed -1'
                        '\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0'
                        '\r\nbTr069SSIDEnable 0\r\nid 33|2,2,0\r\nuUnit 1\r\ncSsidPrefix Guest\r\n'
                        'uRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\n'
                        'uKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\n'
                        'cKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\n'
                        'uKeyType 0\r\nuDefaultKey 1\r\nbEnable 0\r\nbBcastSsid 1\r\ncSsid TP-Link_Guest_5G'
                        '\r\nbSecurityEnable 0\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\n'
                        'uPSKSecOpt 3\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\n'
                        'cPskSecret\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 0\r\n'
                        'bIsLocked 0\r\nbEnRtPIN 0\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\n'
                        'bMwdsEnable 0\r\nbLanAccess 0\r\nSecurityType 1\r\nbApIsolated 1\r\neffectiveTime 0'
                        '\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0'
                        '\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\nid 33|1,9,0\r\nuUnit 9\r\n'
                        'cSsidPrefix IoT\r\nuRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\n'
                        'uPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\n'
                        'uKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\n'
                        'uRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\nbBcastSsid 0'
                        '\r\ncSsid TP-Link_IoT\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3\r\n'
                        'uRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3'
                        '\r\ncRadiusSecret\r\ncPskSecret 11100111\r\nbSecCheck 0\r\nbEnabled 1\r\n'
                        'cUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0\r\nbWifiBtnRecEnable 1'
                        '\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1\r\nSecurityType 2\r\n'
                        'bApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1'
                        '\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0'
                        '\r\nid 33|2,9,0\r\nuUnit 9\r\ncSsidPrefix IoT\r\nuRadiusIp 0.0.0.0\r\n'
                        'uRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0'
                        '\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\n'
                        'cKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\n'
                        'bBcastSsid 0\r\ncSsid TP-Link_IoT\r\nbSecurityEnable 1\r\nuAuthType 3\r\n'
                        'uWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\n'
                        'uPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret 11100111\r\nbSecCheck 0\r\n'
                        'bEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0'
                        '\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1'
                        '\r\nSecurityType 2\r\nbApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1'
                        '\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0'
                        '\r\nbTr069SSIDEnable 0')

STATUS_RESPONSE_WITHOUT_WIFI = ('00000\r\nid 1|1,0,0\r\nauthKey token\r\nreserved\r\nsetWzd 1\r\nmode 4\r\n'
                                'mac 0 40-ae-30-af-c8-72\r\nmac 1 40-ae-30-af-c8-73\r\nwanMacType 0\r\n'
                                'id 4|1,0,0\r\nip 192.168.2.1\r\nmask 255.255.255.0\r\nmode 0\r\n'
                                'smartIp 0\r\ngateway 0.0.0.0\r\n'
                                'id 9|1,0,0\r\nhostName 0 LGwebOSTV\r\nhostName 1 Kaspars\r\n'
                                'hostName 2 Redmi-Note-13-Pro-5G\r\nhostName 3\r\n'
                                'mac 0 60-75-6c-a1-4a-82\r\nmac 1 70-08-10-0b-c6-24\r\n'
                                'mac 2 d6-02-54-6b-67-c4\r\nmac 3 00-00-00-00-00-00\r\n'
                                'ip 0 192.168.2.100\r\nip 1 192.168.2.101\r\nip 2 192.168.2.102\r\nip 3 0.0.0.0\r\n'
                                'state 0 5\r\nstate 1 5\r\nstate 2 5\r\nstate 3 0\r\n'
                                'expires 0 4979\r\nexpires 1 5514\r\nexpires 2 6296\r\nexpires 3 0\r\n'
                                'id 0|1,0,0\r\nmodelName TL-WR844N\r\nhardVer TL-WR844N%201.0')

STATUS_RESPONSE_IOT = ('00000\r\nid 1|1,0,0\r\nauthKey aaa3eKKee\r\nreserved\r\nsetWzd 8\r\nmode 1\r\n'
                       'logLevel 3\r\nfastpath 1\r\nmac 0 00-00-00-00-00-00\r\nmac 1 00-00-00-00-00-01'
                       '\r\nwanMacType 0\r\nmodelMergeCursor 8\r\nid 4|1,0,0\r\nip 192.168.0.1\r\n'
                       'mask 255.255.255.0\r\nmode 0\r\nsmartIp 1\r\ngateway 192.168.0.1\r\nid 23|1,0,0'
                       '\r\nip 100.100.100.100\r\nmask 255.255.252.0\r\ngateway 100.100.105.1\r\n'
                       'dns 0 100.100.0.1\r\ndns 1 100.100.0.1\r\nstatus 1\r\ncode 0\r\nupTime 30814980'
                       '\r\ninPkts 3014881\r\ninOctets 1502000045\r\noutPkts 8216676\r\noutOctets 2500478193'
                       '\r\ninRates 337\r\noutRates 714\r\ndualMode 0\r\ndualIp 0.0.0.0\r\ndualMask 0.0.0.0'
                       '\r\ndualGateway 0.0.0.0\r\ndualDns 0 0.0.0.0\r\ndualDns 1 0.0.0.0\r\ndualCode 0'
                       '\r\ndualStatus 0\r\ninternetDnsDetect 1\r\nid 13|1,0,0\r\nip 0 192.168.0.1\r\n'
                       'ip 1 192.168.0.2\r\nip 2 192.168.0.3\r\nip 3 192.168.0.4\r\nip 4 192.168.0.5'
                       '\r\nip 5 192.168.0.6\r\nmac 0 00-00-00-00-00-02\r\nmac 1 00-00-00-00-00-03'
                       '\r\nmac 2 00-00-00-00-00-04\r\nmac 3 00-00-00-00-00-05\r\nmac 4 00-00-00-00-00-06'
                       '\r\nmac 5 00-00-00-00-00-07\r\nbindEntry 0 0\r\nbindEntry 1 0\r\nbindEntry 2 0'
                       '\r\nbindEntry 3 0\r\nbindEntry 4 0\r\nbindEntry 5 0\r\nstaMgtEntry 0 0\r\n'
                       'staMgtEntry 1 0\r\nstaMgtEntry 2 0\r\nstaMgtEntry 3 0\r\nstaMgtEntry 4 1'
                       '\r\nstaMgtEntry 5 0\r\ntype 0 3\r\ntype 1 1\r\ntype 2 2\r\ntype 3 1\r\ntype 4 13'
                       '\r\ntype 5 0\r\nonline 0 0\r\nonline 1 0\r\nonline 2 1\r\nonline 3 1\r\nonline 4 1'
                       '\r\nonline 5 1\r\nblocked 0 0\r\nblocked 1 0\r\nblocked 2 0\r\nblocked 3 0\r\n'
                       'blocked 4 0\r\nblocked 5 0\r\nqosPrior 0 0\r\nqosPrior 1 0\r\nqosPrior 2 0\r\n'
                       'qosPrior 3 0\r\nqosPrior 4 0\r\nqosPrior 5 0\r\nup 0 0\r\nup 1 0\r\nup 2 30\r\n'
                       'up 3 800\r\nup 4 1824\r\nup 5 600\r\ndown 0 0\r\ndown 1 0\r\ndown 2 200\r\n'
                       'down 3 400\r\ndown 4 800\r\ndown 5 50\r\nupLimit 0 204800\r\nupLimit 1 204800\r\n'
                       'upLimit 2 204800\r\nupLimit 3 204800\r\nupLimit 4 204800\r\nupLimit 5 204800\r\n'
                       'downLimit 0 1048576\r\ndownLimit 1 1048576\r\ndownLimit 2 1048576\r\n'
                       'downLimit 3 1048576\r\ndownLimit 4 1048576\r\ndownLimit 5 1048576\r\nname 0 Laptop'
                       '\r\nname 1 iPhone\r\nname 2 Laptop2\r\nname 3 iPhone2\r\nname 4 IoT_thing\r\n'
                       'name 5 PC\r\nuBandwidth 0 0\r\nuBandwidth 1 0\r\nuBandwidth 2 0\r\nuBandwidth 3 0'
                       '\r\nuBandwidth 4 0\r\nuBandwidth 5 0\r\nuStandard 0 0\r\nuStandard 1 0\r\n'
                       'uStandard 2 0\r\nuStandard 3 2\r\nuStandard 4 2\r\nuStandard 5 0\r\ndevType 0 0'
                       '\r\ndevType 1 0\r\ndevType 2 0\r\ndevType 3 0\r\ndevType 4 0\r\ndevType 5 0\r\n'
                       'priTime 0 0\r\npriTime 1 0\r\npriTime 2 0\r\npriTime 3 0\r\npriTime 4 0\r\n'
                       'priTime 5 0\r\nleaseTime 0 0\r\nleaseTime 1 0\r\nleaseTime 2 0\r\nleaseTime 3 0'
                       '\r\nleaseTime 4 0\r\nleaseTime 5 0\r\ntotalVal 0 450\r\ntotalVal 1 5\r\n'
                       'totalVal 2 13\r\ntotalVal 3 956\r\ntotalVal 4 13\r\ntotalVal 5 53\r\ntotalUnit 0 2'
                       '\r\ntotalUnit 1 2\r\ntotalUnit 2 2\r\ntotalUnit 3 2\r\ntotalUnit 4 2\r\n'
                       'totalUnit 5 2\r\ndhcpsEntry 0 0\r\ndhcpsEntry 1 0\r\ndhcpsEntry 2 0\r\n'
                       'dhcpsEntry 3 0\r\ndhcpsEntry 4 0\r\ndhcpsEntry 5 0\r\nduration 0 0\r\n'
                       'duration 1 0\r\nduration 2 0\r\nduration 3 73\r\nduration 4 5388\r\n'
                       'duration 5 8559\r\ntxRate 0 0\r\ntxRate 1 0\r\ntxRate 2 0\r\ntxRate 3 156\r\n'
                       'txRate 4 130\r\ntxRate 5 0\r\nrxRate 0 0\r\nrxRate 1 0\r\nrxRate 2 0\r\n'
                       'rxRate 3 130\r\nrxRate 4 173\r\nrxRate 5 0\r\naveRssi 0 0\r\naveRssi 1 0\r\n'
                       'aveRssi 2 0\r\naveRssi 3 33\r\naveRssi 4 46\r\naveRssi 5 0\r\nslEnable 0 0\r\n'
                       'slEnable 1 0\r\nslEnable 2 0\r\nslEnable 3 0\r\nslEnable 4 0\r\nslEnable 5 0'
                       '\r\npriScheStatus 0 0\r\npriScheStatus 1 0\r\npriScheStatus 2 0\r\n'
                       'priScheStatus 3 0\r\npriScheStatus 4 0\r\npriScheStatus 5 0\r\nstart 0 0\r\n'
                       'start 1 0\r\nstart 2 0\r\nstart 3 0\r\nstart 4 0\r\nstart 5 0\r\nend 0 0\r\n'
                       'end 1 0\r\nend 2 0\r\nend 3 0\r\nend 4 0\r\nend 5 0\r\nday 0 0\r\nday 1 0\r\n'
                       'day 2 0\r\nday 3 0\r\nday 4 0\r\nday 5 0\r\nstartMin 0 0\r\nstartMin 1 0\r\n'
                       'startMin 2 0\r\nstartMin 3 0\r\nstartMin 4 0\r\nstartMin 5 0\r\nendMin 0 0\r\n'
                       'endMin 1 0\r\nendMin 2 0\r\nendMin 3 0\r\nendMin 4 0\r\nendMin 5 0\r\nrate 0 0'
                       '\r\nrate 1 0\r\nrate 2 0\r\nrate 3 156\r\nrate 4 173\r\nrate 5 0\r\ntxPkt 0 0'
                       '\r\ntxPkt 1 0\r\ntxPkt 2 0\r\ntxPkt 3 42602\r\ntxPkt 4 119683\r\ntxPkt 5 0'
                       '\r\nrxPkt 0 0\r\nrxPkt 1 0\r\nrxPkt 2 0\r\nrxPkt 3 6343\r\nrxPkt 4 275076\r\n'
                       'rxPkt 5 0\r\nid 33|1,1,0\r\nuUnit 0\r\ncSsidPrefix\r\nuRadiusIp 0.0.0.0\r\n'
                       'uRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0'
                       '\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\n'
                       'cKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\n'
                       'bBcastSsid 1\r\ncSsid TP-Link\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3'
                       '\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3'
                       '\r\ncRadiusSecret\r\ncPskSecret admin\r\nbSecCheck 0\r\nbEnabled 1\r\n'
                       'cUsrPIN 11100111\r\nbConfigured 1\r\nbIsLocked 0\r\nbEnRtPIN 1\r\n'
                       'bWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1'
                       '\r\nSecurityType 2\r\nbApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1'
                       '\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 1\r\nbTr069APEnable 0'
                       '\r\nbTr069SSIDEnable 0\r\nid 33|2,1,0\r\nuUnit 0\r\ncSsidPrefix\r\nuRadiusIp 0.0.0.0'
                       '\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0'
                       '\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\n'
                       'cKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\n'
                       'bBcastSsid 1\r\ncSsid TP-Link\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3'
                       '\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3'
                       '\r\ncRadiusSecret\r\ncPskSecret admin\r\nbSecCheck 0\r\nbEnabled 1\r\n'
                       'cUsrPIN 11100111\r\nbConfigured 1\r\nbIsLocked 0\r\nbEnRtPIN 1\r\nbWifiBtnRecEnable 1'
                       '\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1\r\nSecurityType 2\r\n'
                       'bApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\n'
                       'bwCtrlEnable 0\r\nenableBackup 1\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\n'
                       'id 33|1,2,0\r\nuUnit 1\r\ncSsidPrefix Guest\r\nuRadiusIp 0.0.0.0\r\n'
                       'uRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0'
                       '\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\n'
                       'cKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 0\r\n'
                       'bBcastSsid 1\r\ncSsid TP-Link_Guest\r\nbSecurityEnable 0\r\nuAuthType 3\r\n'
                       'uWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 3\r\nuRadiusEncryptType 1\r\n'
                       'uPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret\r\nbSecCheck 0\r\nbEnabled 1'
                       '\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0\r\n'
                       'bWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 0'
                       '\r\nSecurityType 1\r\nbApIsolated 1\r\neffectiveTime 0\r\nuMaxUploadSpeed -1'
                       '\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0'
                       '\r\nbTr069SSIDEnable 0\r\nid 33|2,2,0\r\nuUnit 1\r\ncSsidPrefix Guest\r\n'
                       'uRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\n'
                       'uKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\n'
                       'cKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\n'
                       'uKeyType 0\r\nuDefaultKey 1\r\nbEnable 0\r\nbBcastSsid 1\r\ncSsid TP-Link_Guest_5G'
                       '\r\nbSecurityEnable 0\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\n'
                       'uPSKSecOpt 3\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\n'
                       'cPskSecret\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 0\r\n'
                       'bIsLocked 0\r\nbEnRtPIN 0\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\n'
                       'bMwdsEnable 0\r\nbLanAccess 0\r\nSecurityType 1\r\nbApIsolated 1\r\neffectiveTime 0'
                       '\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0'
                       '\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0')


class ResponseMock():
    def __init__(self, text, status_code=0):
        self.text = text
        self.status_code = status_code


class TplinkC80RouterTest(TplinkC80Router):
    response = ''

    def request(self, code: int, asyn: int, use_token: bool = False, data: str = None) -> dict | None:

        # Responses
        if code == 2 and asyn == 1:
            if use_token is False:
                if data == '0|1,0,0':
                    # Supports
                    return ResponseMock(self.response, 200)
                else:
                    # Authorization
                    return ResponseMock('blabla\r\nblabla\r\nblabla\r\nauthinfo1\r\nauthinfo2')
            elif use_token is True:
                return ResponseMock(self.response)
        elif (code == 16 or code == 7) and asyn == 0:
            if use_token is False:
                # Authorization
                return ResponseMock('00000\r\n010001\r\nBC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E'
                                    '9D3DE83FE70C2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3\r\n12345656')
            elif use_token is True:
                # Authorization
                return ResponseMock('00000')

        raise ClientException()

    def set_encrypted_response(self, response_text) -> None:
        self.response = self._encrypt_body(response_text).split('data=')[1]


class TestTPLinkClient(TestCase):

    def test_supports(self) -> None:
        response = ('00000\r\nid 0|1,0,0\r\nfullName AC1900%20MU-MIMO%20Wi-Fi%20Router\r\nfacturer TP-Link\r\nmodelName'
                    ' Archer%20C80\r\nmodelVer 2.20\r\nsoftVer 1.13.15%20Build%20240812%20Rel.53972n(4555)\r\nhardVer'
                    ' Archer%20C80%202.20\r\nspecialId 0x5545\r\ncountryCode 0x455a\r\nmainVer 0x5a010d0f\r\nminorVer'
                    ' 0x1\r\nfacturerType 0')

        client = TplinkC80RouterTest('', '')
        client.response = response
        supports = client.supports()
        self.assertTrue(supports)

    def test_authorize(self) -> None:
        client = TplinkC80RouterTest('', '')
        client.authorize()

        encryption = client._encryption
        self.assertEqual(encryption.ee_rsa, '010001')
        self.assertEqual(encryption.nn_rsa, 'BC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E9D3DE83FE70C'
                                            '2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3')
        self.assertEqual(encryption.seq, '12345656')

    def test_get_firmware(self) -> None:
        response = ('00000\r\nid 0|1,0,0\r\nfullName AC1900%20MU-MIMO%20Wi-Fi%20Router\r\nfacturer TP-Link\r\nmodelName'
                    ' Archer%20C80\r\nmodelVer 2.20\r\nsoftVer 1.13.15%20Build%20240812%20Rel.53972n(4555)\r\nhardVer'
                    ' Archer%20C80%202.20\r\nspecialId 0x5545\r\ncountryCode 0x455a\r\nmainVer 0x5a010d0f\r\nminorVer'
                    ' 0x1\r\nfacturerType 0')

        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(response)

        firmware = client.get_firmware()

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, 'Archer C80 2.20')
        self.assertEqual(firmware.model, 'Archer C80')
        self.assertEqual(firmware.firmware_version, '1.13.15 Build 240812 Rel.53972n(4555)')

    def test_get_ipv4_status(self) -> None:

        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(IPV4_STATUS_RESPONSE)

        ipv4_status: IPv4Status = client.get_ipv4_status()

        self.assertIsInstance(ipv4_status, IPv4Status)
        self.assertEqual(ipv4_status.wan_macaddress, EUI48('00-00-00-00-00-01'))
        self.assertEqual(ipv4_status._wan_ipv4_ipaddr, IPv4Address('1.0.1.1'))
        self.assertEqual(ipv4_status._wan_ipv4_gateway, IPv4Address('1.0.0.1'))
        self.assertEqual(ipv4_status._wan_ipv4_conntype, 'Dynamic IP')
        self.assertEqual(ipv4_status._wan_ipv4_netmask, IPv4Address('255.255.252.0'))
        self.assertEqual(ipv4_status._wan_ipv4_pridns, IPv4Address('8.8.8.8'))
        self.assertEqual(ipv4_status._wan_ipv4_snddns, IPv4Address('8.8.8.8'))
        self.assertEqual(ipv4_status._lan_macaddr, EUI48('00-00-00-00-00-00'))
        self.assertEqual(ipv4_status._lan_ipv4_ipaddr, IPv4Address('192.168.0.1'))
        self.assertEqual(ipv4_status.lan_ipv4_dhcp_enable, True)
        self.assertEqual(ipv4_status._lan_ipv4_netmask, IPv4Address('255.255.255.0'))

    def test_get_ipv6_status(self) -> None:
        response = (
            '00000\r\nid 45|1,0,0\r\n'
            'status 9\r\nerrorCode 0\r\ninterfaceType 0\r\nipGetMethod 0\r\nraReceived 1\r\n'
            'getIpWithDhcp 1\r\ngetDnsWithDhcp 1\r\nglobalIp 2401:0005:1000::48\r\n'
            'prefixAddr ::\r\nprefixLen 64\r\ngateway fe80::0001:0001:0001:3040\r\n'
            'dns 0 2401:380:1::61\r\ndns 1 2401:380:1::62\r\n'
            'linkLocalIp fe80::0001:0001:0001:8a86\r\n'
            'id 48|1,0,0\r\n'
            'linkLocalIp fe80::0001:0001:0001:e986\r\n'
            'prefixAddr 2401:0005:1000:4800::\r\nprefixLen 64\r\n'
            'lanUnicastIp 2401:0001:0001:0001:0001:0001:0001:e986'
        )

        client = TplinkC80RouterTest('', '')
        client.authorize()
        client.set_encrypted_response(response)

        ipv6_status = client.get_ipv6_status()

        self.assertIsInstance(ipv6_status, IPv6Status)
        self.assertEqual(ipv6_status.wan_ipv6_enabled, True)
        self.assertEqual(ipv6_status.wan_ipv6_conn_status, 'Connected')
        self.assertEqual(ipv6_status.wan_ipv6_addr_type, 'DHCPv6')
        self.assertEqual(ipv6_status.wan_ipv6_addr, '2401:5:1000::48')
        self.assertEqual(ipv6_status.wan_ipv6_gateway, 'fe80::1:1:1:3040')
        self.assertEqual(ipv6_status.wan_ipv6_pridns, IPv6Address('2401:380:1::61'))
        self.assertEqual(ipv6_status.wan_ipv6_snddns, IPv6Address('2401:380:1::62'))
        self.assertEqual(ipv6_status.ipv6_site_prefix, '2401:5:1000:4800::')
        self.assertEqual(ipv6_status.ipv6_site_prefix_length, '64')
        self.assertEqual(ipv6_status.wan_ipv6_conntype, None)

    def test_get_ipv6_status_disabled(self) -> None:
        response = (
            '00000\r\nid 45|1,0,0\r\n'
            'status 0\r\nerrorCode 0\r\ninterfaceType 0\r\nipGetMethod 0\r\nraReceived 0\r\n'
            'getIpWithDhcp 0\r\ngetDnsWithDhcp 0\r\nglobalIp ::\r\n'
            'prefixAddr ::\r\nprefixLen 0\r\ngateway ::\r\n'
            'dns 0 ::\r\ndns 1 ::\r\nlinkLocalIp ::\r\n'
            'id 48|1,0,0\r\n'
            'linkLocalIp ::\r\nprefixAddr ::\r\nprefixLen 0\r\nlanUnicastIp ::'
        )

        client = TplinkC80RouterTest('', '')
        client.authorize()
        client.set_encrypted_response(response)

        ipv6_status = client.get_ipv6_status()

        self.assertIsInstance(ipv6_status, IPv6Status)
        self.assertEqual(ipv6_status.wan_ipv6_enabled, False)
        self.assertEqual(ipv6_status.wan_ipv6_conn_status, 'Disabled')
        self.assertEqual(ipv6_status.wan_ipv6_addr_type, 'Unknown')
        self.assertEqual(ipv6_status.wan_ipv6_addr, '::')
        self.assertEqual(ipv6_status.wan_ipv6_gateway, '::')
        self.assertEqual(ipv6_status.wan_ipv6_pridns, IPv6Address('::'))
        self.assertEqual(ipv6_status.wan_ipv6_snddns, IPv6Address('::'))
        self.assertEqual(ipv6_status.ipv6_site_prefix, '::')
        self.assertEqual(ipv6_status.ipv6_site_prefix_length, '0')

    def test_get_ipv4_reservations(self) -> None:
        response = ('00000\r\nid 12|1,0,0\r\nip 0 192.168.0.112\r\nip 1 0.0.0.0\r\nmac 0 00-00-00-00-00-00\r\n'
                    'mac 1 00-00-00-00-00-01\r\nreserved 0\r\nreserved 1\r\nbindEntry 0 0\r\nbindEntry 1 0\r\n'
                    'staMgtEntry 0 0\r\nstaMgtEntry 1 1\r\nname 0 Galaxy-S21\r\nname 1 Camera\r\nreserved_name 0\r\n'
                    'reserved_name 1\r\nblocked 0 0\r\nblocked 1 0\r\nupLimit 0 0\r\nupLimit 1 0\r\ndownLimit 0 0'
                    '\r\ndownLimit 1 0\r\nqosEntry 0 0\r\nqosEntry 1 0\r\npriTime 0 0\r\npriTime 1 0\r\n'
                    'dhcpsEntry 0 1\r\ndhcpsEntry 1 0\r\ndhcpsEnable 0 1\r\ndhcpsEnable 1 0\r\nslEnable 0 0\r\n'
                    'slEnable 1 0\r\nstart 0 0\r\nstart 1 0\r\nend 0 0\r\nend 1 0\r\nday 0 0\r\nday 1 0\r\n'
                    'startMin 0 0\r\nstartMin 1 0\r\nendMin 0 0\r\nendMin 1 0\r\ndevType 0 0\r\ndevType 1 0\r\n'
                    'reserved2 0 0\r\nreserved2 1 0\r\ndisable 1')

        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(response)

        ipv4_reservations: list[IPv4Reservation] = client.get_ipv4_reservations()
        ipv4_reservation: IPv4Reservation = ipv4_reservations[0]

        self.assertIsInstance(ipv4_reservation, IPv4Reservation)
        self.assertEqual(ipv4_reservation.macaddress, EUI48('00-00-00-00-00-00'))
        self.assertEqual(ipv4_reservation.ipaddress, IPv4Address('192.168.0.112'))
        self.assertEqual(ipv4_reservation.hostname, 'Galaxy-S21')
        self.assertEqual(ipv4_reservation.enabled, True)

    def test_get_dhcp_leases(self) -> None:
        response = ('00000\r\nid 9|1,0,0\r\nhostName 0 Galaxy-S21\r\nhostName 1 iPhone\r\nhostName 2 PC\r\n'
                    'hostName 3 Laptop\r\nmac 0 00-00-00-00-00-00\r\nmac 1 00-00-00-00-00-01\r\n'
                    'mac 2 00-00-00-00-00-02\r\nmac 3 00-00-00-00-00-03\r\nreserved 0\r\nreserved 1'
                    '\r\nreserved 2\r\nreserved 3\r\nstate 0 5\r\nstate 1 5\r\nstate 2 5\r\nstate 3 5'
                    '\r\nip 0 192.168.0.112\r\nip 1 192.168.0.101\r\nip 2 192.168.0.245\r\nip 3 192.168.0.186'
                    '\r\nexpires 0 4294967295\r\nexpires 1 3669\r\nexpires 2 4025\r\nexpires 3 4202')

        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(response)

        dhcp_leases: list[IPv4DHCPLease] = client.get_dhcp_leases()

        self.assertIsInstance(dhcp_leases[0], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[0].macaddress, EUI48('00-00-00-00-00-00'))
        self.assertEqual(dhcp_leases[0].ipaddress, IPv4Address('192.168.0.112'))
        self.assertEqual(dhcp_leases[0].hostname, 'Galaxy-S21')
        self.assertEqual(dhcp_leases[0].lease_time, 'expires 4294967295')

        self.assertIsInstance(dhcp_leases[1], IPv4DHCPLease)
        self.assertEqual(dhcp_leases[1].macaddress, EUI48('00-00-00-00-00-01'))
        self.assertEqual(dhcp_leases[1].ipaddress, IPv4Address('192.168.0.101'))
        self.assertEqual(dhcp_leases[1].hostname, 'iPhone')
        self.assertEqual(dhcp_leases[1].lease_time, 'expires 3669')

    def test_get_vpn_status(self) -> None:
        response = '00000\r\nid 22|1,0,0\r\nenable 1\r\nneedPnpDetect 0\r\nocnDetect 0\r\n' \
                   'reserved\r\nlinkMode 0\r\nlinkType 4'

        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(response)

        vpn_status: VPNStatus = client.get_vpn_status()

        self.assertIsInstance(vpn_status, VPNStatus)
        self.assertEqual(vpn_status.openvpn_clients_total, 0)
        self.assertEqual(vpn_status.pptpvpn_clients_total, 0)
        self.assertEqual(vpn_status.pptpvpn_enable, True)

    def test_get_status_with_wifi(self) -> None:
        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(STATUS_RESPONSE_TEXT)
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, '00-00-00-00-00-01')
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, '00-00-00-00-00-00')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '100.100.100.100')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.0.1')
        self.assertEqual(status.wan_ipv4_gateway, '100.100.105.1')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertEqual(status.wired_total, 1)
        self.assertEqual(status.wifi_clients_total, 1)
        self.assertEqual(status.guest_clients_total, 1)
        self.assertEqual(status.clients_total, 4)
        self.assertEqual(status.iot_clients_total, 1)
        self.assertFalse(status.guest_2g_enable)
        self.assertFalse(status.guest_5g_enable)
        self.assertTrue(status.iot_2g_enable)
        self.assertTrue(status.iot_5g_enable)
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertEqual(status.wan_ipv4_uptime, 308149)
        self.assertEqual(status.mem_usage, None)
        self.assertEqual(status.cpu_usage, None)
        self.assertEqual(len(status.devices), 6)

        device = status.devices[0]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.UNKNOWN)
        self.assertEqual(device.macaddr, '00-00-00-00-00-02')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '192.168.0.1')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'Laptop')
        self.assertEqual(device.up_speed, 0)
        self.assertEqual(device.down_speed, 0)
        self.assertEqual(device.active, False)

        device = status.devices[1]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.UNKNOWN)
        self.assertEqual(device.macaddr, '00-00-00-00-00-03')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '192.168.0.2')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'iPhone')
        self.assertEqual(device.up_speed, 0)
        self.assertEqual(device.down_speed, 0)
        self.assertEqual(device.active, False)

        device = status.devices[2]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.GUEST_2G)
        self.assertEqual(device.macaddr, '00-00-00-00-00-04')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '192.168.0.3')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'Laptop2')
        self.assertEqual(device.up_speed, 30)
        self.assertEqual(device.down_speed, 200)
        self.assertEqual(device.active, True)

        device = status.devices[3]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.HOST_2G)
        self.assertEqual(device.macaddr, '00-00-00-00-00-05')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '192.168.0.4')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'iPhone2')
        self.assertEqual(device.up_speed, 800)
        self.assertEqual(device.down_speed, 400)
        self.assertEqual(device.active, True)

        device = status.devices[4]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.IOT_2G)
        self.assertEqual(device.macaddr, '00-00-00-00-00-06')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '192.168.0.5')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'IoT_thing')
        self.assertEqual(device.up_speed, 1824)
        self.assertEqual(device.down_speed, 800)
        self.assertEqual(device.active, True)

        device = status.devices[5]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.WIRED)
        self.assertEqual(device.macaddr, '00-00-00-00-00-07')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '192.168.0.6')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'PC')
        self.assertEqual(device.up_speed, 600)
        self.assertEqual(device.down_speed, 50)
        self.assertEqual(device.active, True)

    def test_get_status_without_iot(self) -> None:
        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(STATUS_RESPONSE_IOT)
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, '00-00-00-00-00-01')
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, '00-00-00-00-00-00')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '100.100.100.100')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '192.168.0.1')
        self.assertEqual(status.wan_ipv4_gateway, '100.100.105.1')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertEqual(status.wired_total, 1)
        self.assertEqual(status.wifi_clients_total, 1)
        self.assertEqual(status.guest_clients_total, 1)
        self.assertEqual(status.clients_total, 4)
        self.assertEqual(status.iot_clients_total, 1)
        self.assertFalse(status.guest_2g_enable)
        self.assertFalse(status.guest_5g_enable)
        self.assertIsNone(status.iot_2g_enable)
        self.assertIsNone(status.iot_5g_enable)
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertEqual(status.wan_ipv4_uptime, 308149)
        self.assertEqual(status.mem_usage, None)
        self.assertEqual(status.cpu_usage, None)
        self.assertEqual(len(status.devices), 6)

    def test_get_status_without_wifi(self) -> None:
        client = TplinkC80RouterTest('http://192.168.0.68', '')
        client.authorize()

        client.set_encrypted_response(STATUS_RESPONSE_WITHOUT_WIFI)
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.lan_macaddr, '40-AE-30-AF-C8-72')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_macaddr, '40-AE-30-AF-C8-73')
        self.assertEqual(status.lan_ipv4_addr, '192.168.2.1')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.wan_ipv4_addr, '192.168.0.68')
        self.assertEqual(status.conn_type, 'Router/AP')
        self.assertTrue(status.wifi_2g_enable)
        self.assertEqual(status.clients_total, 3)
        self.assertEqual(status.wifi_clients_total, 3)
        self.assertEqual(status.wired_total, 0)
        self.assertEqual(len(status.devices), 3)

        device = status.devices[0]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.HOST_2G)
        self.assertEqual(device.hostname, 'LGwebOSTV')
        self.assertEqual(device.ipaddr, '192.168.2.100')
        self.assertEqual(device.macaddr, '60-75-6C-A1-4A-82')

        device = status.devices[2]
        self.assertEqual(device.hostname, 'Redmi-Note-13-Pro-5G')
        self.assertEqual(device.ipaddr, '192.168.2.102')
        self.assertEqual(device.macaddr, 'D6-02-54-6B-67-C4')

    def test_get_ipv4(self) -> None:
        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(IPV4_RESPONSE_TEXT)
        ipv4status: IPv4Status = client.get_ipv4_status()

        self.assertIsInstance(ipv4status, IPv4Status)
        self.assertEqual(ipv4status._wan_macaddr, EUI48('00-00-00-00-00-01'))
        self.assertEqual(ipv4status._wan_ipv4_ipaddr, IPv4Address('1.1.1.1'))
        self.assertEqual(ipv4status._wan_ipv4_gateway, IPv4Address('1.1.1.2'))
        self.assertEqual(ipv4status._wan_ipv4_conntype, 'Dynamic IP')
        self.assertEqual(ipv4status._wan_ipv4_netmask, IPv4Address('255.255.252.0'))
        self.assertEqual(ipv4status._wan_ipv4_pridns, IPv4Address('5.8.8.8'))
        self.assertEqual(ipv4status._wan_ipv4_snddns, IPv4Address('5.8.8.8'))
        self.assertEqual(ipv4status._lan_macaddr, EUI48('00-00-00-00-00-00'))
        self.assertEqual(ipv4status._lan_ipv4_ipaddr, IPv4Address('192.168.0.1'))
        self.assertEqual(ipv4status.lan_ipv4_dhcp_enable, True)
        self.assertEqual(ipv4status._lan_ipv4_netmask, IPv4Address('255.255.255.0'))

    def test_get_status_with_ipv6(self) -> None:
        """IPv6 on Status from a separate 45|1,0,0 probe (C24 capture from PR #197)."""
        ipv6_blocks = {
            RouterConstants.IPV6_WAN_REQUEST: [
                'status 9',
                'errorCode 0',
                'getIpWithDhcp 1',
                'globalIp 2401:0005:1000::48',
                'gateway fe80::0001:0001:0001:3040',
                'dns 0 2401:380:1::61',
                'dns 1 2401:380:1::62',
            ],
        }

        class Client(TplinkC80RouterTest):
            def _return_data_block(self, request_text: str):
                if request_text == RouterConstants.IPV6_WAN_REQUEST:
                    return ipv6_blocks
                return super()._return_data_block(request_text)

        client = Client('', '')
        client.authorize()
        client.set_encrypted_response(STATUS_RESPONSE_TEXT)
        status = client.get_status()

        self.assertTrue(client._ipv6_support)
        self.assertTrue(status.wan_ipv6_enabled)
        self.assertEqual(status.wan_ipv6_addr, '2401:5:1000::48')
        self.assertIsInstance(status._wan_ipv6_addr, IPv6Address)

    def test_get_status_ipv6_disabled(self) -> None:
        ipv6_blocks = {
            RouterConstants.IPV6_WAN_REQUEST: [
                'status 0',
                'globalIp ::',
                'gateway ::',
                'dns 0 ::',
                'dns 1 ::',
            ],
        }

        class Client(TplinkC80RouterTest):
            def _return_data_block(self, request_text: str):
                if request_text == RouterConstants.IPV6_WAN_REQUEST:
                    return ipv6_blocks
                return super()._return_data_block(request_text)

        client = Client('', '')
        client.authorize()
        client.set_encrypted_response(STATUS_RESPONSE_TEXT)
        status = client.get_status()

        self.assertTrue(client._ipv6_support)
        self.assertFalse(status.wan_ipv6_enabled)
        self.assertEqual(status.wan_ipv6_addr, '::')

    def test_get_status_ipv6_unsupported_disables_flag(self) -> None:
        """Missing WAN IPv6 block must not fake disabled; further probes stop."""
        ipv6_calls = {'n': 0}

        class Client(TplinkC80RouterTest):
            def _return_data_block(self, request_text: str):
                if request_text == RouterConstants.IPV6_WAN_REQUEST:
                    ipv6_calls['n'] += 1
                    # Non-empty response without 45|1,0,0 (same trap as shared test fixtures).
                    return {'1|1,0,0': ['mac 0 00-00-00-00-00-00']}
                return super()._return_data_block(request_text)

        client = Client('', '')
        client.authorize()
        client.set_encrypted_response(STATUS_RESPONSE_TEXT)
        status = client.get_status()

        self.assertFalse(client._ipv6_support)
        self.assertIsNone(status.wan_ipv6_enabled)
        self.assertIsNone(status.wan_ipv6_addr)
        self.assertEqual(ipv6_calls['n'], 1)

        client.get_status()
        self.assertEqual(ipv6_calls['n'], 1)

    def test_get_status_ipv6_error_disables_flag(self) -> None:
        ipv6_calls = {'n': 0}

        class Client(TplinkC80RouterTest):
            def _return_data_block(self, request_text: str):
                if request_text == RouterConstants.IPV6_WAN_REQUEST:
                    ipv6_calls['n'] += 1
                    raise ClientException('IPv6 attrs not supported')
                return super()._return_data_block(request_text)

        client = Client('', '')
        client.authorize()
        client.set_encrypted_response(STATUS_RESPONSE_TEXT)
        status = client.get_status()

        self.assertFalse(client._ipv6_support)
        self.assertIsNone(status.wan_ipv6_enabled)
        self.assertEqual(ipv6_calls['n'], 1)

        client.get_status()
        self.assertEqual(ipv6_calls['n'], 1)


class TestTplinkC80RouterSslContext(TestCase):

    def test_ssl_context_enables_legacy_renegotiation(self) -> None:
        import ssl

        ctx = TplinkC80Router._build_ssl_context(True)
        if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
            self.assertTrue(ctx.options & ssl.OP_LEGACY_SERVER_CONNECT)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_ssl_context_unverified_when_verify_off(self) -> None:
        import ssl

        ctx = TplinkC80Router._build_ssl_context(False)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

    def test_ssl_context_skips_loading_certs_when_verify_off(self) -> None:
        import ssl

        with patch.object(ssl.SSLContext, 'load_default_certs') as load_certs:
            TplinkC80Router._build_ssl_context(False)
        load_certs.assert_not_called()

    def test_http_host_does_not_build_ssl_context(self) -> None:
        with patch.object(TplinkC80Router, '_build_ssl_context') as build_ctx:
            client = TplinkC80Router('http://192.168.0.1', 'password', verify_ssl=True)
        build_ctx.assert_not_called()
        self.assertIs(client._session.verify, True)

    def test_http_host_respects_verify_ssl_false(self) -> None:
        with patch.object(TplinkC80Router, '_build_ssl_context') as build_ctx:
            client = TplinkC80Router('http://192.168.0.1', 'password', verify_ssl=False)
        build_ctx.assert_not_called()
        self.assertIs(client._session.verify, False)

    def test_https_host_uses_ssl_context(self) -> None:
        import ssl

        sentinel = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with patch.object(TplinkC80Router, '_build_ssl_context', return_value=sentinel) as build_ctx:
            client = TplinkC80Router('https://192.168.0.1', 'password', verify_ssl=True)
        build_ctx.assert_called_once_with(True)
        self.assertIs(client._session.verify, sentinel)


if __name__ == '__main__':
    main()
