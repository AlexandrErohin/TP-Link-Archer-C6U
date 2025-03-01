from unittest import main, TestCase
from macaddress import EUI48
from ipaddress import IPv4Address
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device
from json import loads
from tplinkrouterc6u import (
    TplinkRouter,
    Connection,
    Status,
    Device,
    ClientException,
)
from tplinkrouterc6u.client.c80 import TplinkC80Router

class ResponseMock():
    def __init__(self, text):
        self.text = text

class TplinkC80RouterTest(TplinkC80Router):
    response = ''
    def request(self, code: int, asyn: int, token: str = None, data: str = None) -> dict | None:

        # Responses
        if code == 2 and asyn == 1:
            if token is None:
                if data == '0|1,0,0':
                    # Supports
                    return ResponseMock(self.response)
                else:
                    # Authorization
                    return ResponseMock('blabla\r\nblabla\r\nblabla\r\nauthinfo1\r\nauthinfo2')
            elif token is not None:
                return ResponseMock(self.response)
        elif (code == 16 or code == 7) and asyn == 0:
            if token is None:
                # Authorization
                return ResponseMock('00000\r\n010001\r\nBC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E9D3DE83FE70C2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3\r\n12345656')
            elif token is not None:
                # Authorization
                return ResponseMock('00000')
        
        raise ClientException()
    
    def set_encrypted_response(self, response_text) -> None:
        self.response = self._encrypt_body(response_text).split('data=')[1]

class TestTPLinkClient(TestCase):

    def test_supports(self) -> None:
        response = '00000\r\nid 0|1,0,0\r\nfullName AC1900%20MU-MIMO%20Wi-Fi%20Router\r\nfacturer TP-Link\r\nmodelName Archer%20C80\r\nmodelVer 2.20\r\nsoftVer 1.13.15%20Build%20240812%20Rel.53972n(4555)\r\nhardVer Archer%20C80%202.20\r\nspecialId 0x5545\r\ncountryCode 0x455a\r\nmainVer 0x5a010d0f\r\nminorVer 0x1\r\nfacturerType 0'

        client = TplinkC80RouterTest('', '')
        client.response = response
        supports = client.supports()
        self.assertTrue(supports)

    def test_authorize(self) -> None:        
        client = TplinkC80RouterTest('', '')
        client.authorize()
        
        encryption = client._encryption
        self.assertEqual(encryption.ee_rsa, '010001')
        self.assertEqual(encryption.nn_rsa, 'BC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E9D3DE83FE70C2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3')
        self.assertEqual(encryption.seq, '12345656')

    def test_get_firmware(self) -> None:
        response = '00000\r\nid 0|1,0,0\r\nfullName AC1900%20MU-MIMO%20Wi-Fi%20Router\r\nfacturer TP-Link\r\nmodelName Archer%20C80\r\nmodelVer 2.20\r\nsoftVer 1.13.15%20Build%20240812%20Rel.53972n(4555)\r\nhardVer Archer%20C80%202.20\r\nspecialId 0x5545\r\ncountryCode 0x455a\r\nmainVer 0x5a010d0f\r\nminorVer 0x1\r\nfacturerType 0'

        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(response)
        
        firmware = client.get_firmware()

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, 'Archer C80 2.20')
        self.assertEqual(firmware.model, 'Archer C80')
        self.assertEqual(firmware.firmware_version, '1.13.15 Build 240812 Rel.53972n(4555)')

    def test_get_status(self) -> None:
        status_response_text = '00000\r\nid 1|1,0,0\r\nauthKey aaa3eKKee\r\nreserved\r\nsetWzd 8\r\nmode 1\r\nlogLevel 3\r\nfastpath 1\r\nmac 0 00-00-00-00-00-00\r\nmac 1 00-00-00-00-00-01\r\nwanMacType 0\r\nmodelMergeCursor 8\r\nid 4|1,0,0\r\nip 192.168.0.1\r\nmask 255.255.255.0\r\nmode 0\r\nsmartIp 1\r\ngateway 192.168.0.1\r\nid 23|1,0,0\r\nip 100.100.100.100\r\nmask 255.255.252.0\r\ngateway 100.100.105.1\r\ndns 0 100.100.0.1\r\ndns 1 100.100.0.1\r\nstatus 1\r\ncode 0\r\nupTime 30814980\r\ninPkts 3014881\r\ninOctets 1502000045\r\noutPkts 8216676\r\noutOctets 2500478193\r\ninRates 337\r\noutRates 714\r\ndualMode 0\r\ndualIp 0.0.0.0\r\ndualMask 0.0.0.0\r\ndualGateway 0.0.0.0\r\ndualDns 0 0.0.0.0\r\ndualDns 1 0.0.0.0\r\ndualCode 0\r\ndualStatus 0\r\ninternetDnsDetect 1\r\nid 13|1,0,0\r\nip 0 192.168.0.1\r\nip 1 192.168.0.2\r\nip 2 192.168.0.3\r\nip 3 192.168.0.4\r\nip 4 192.168.0.5\r\nip 5 192.168.0.6\r\nmac 0 00-00-00-00-00-02\r\nmac 1 00-00-00-00-00-03\r\nmac 2 00-00-00-00-00-04\r\nmac 3 00-00-00-00-00-05\r\nmac 4 00-00-00-00-00-06\r\nmac 5 00-00-00-00-00-07\r\nbindEntry 0 0\r\nbindEntry 1 0\r\nbindEntry 2 0\r\nbindEntry 3 0\r\nbindEntry 4 0\r\nbindEntry 5 0\r\nstaMgtEntry 0 0\r\nstaMgtEntry 1 0\r\nstaMgtEntry 2 0\r\nstaMgtEntry 3 0\r\nstaMgtEntry 4 1\r\nstaMgtEntry 5 0\r\ntype 0 3\r\ntype 1 1\r\ntype 2 2\r\ntype 3 1\r\ntype 4 13\r\ntype 5 0\r\nonline 0 0\r\nonline 1 0\r\nonline 2 1\r\nonline 3 1\r\nonline 4 1\r\nonline 5 1\r\nblocked 0 0\r\nblocked 1 0\r\nblocked 2 0\r\nblocked 3 0\r\nblocked 4 0\r\nblocked 5 0\r\nqosPrior 0 0\r\nqosPrior 1 0\r\nqosPrior 2 0\r\nqosPrior 3 0\r\nqosPrior 4 0\r\nqosPrior 5 0\r\nup 0 0\r\nup 1 0\r\nup 2 30\r\nup 3 800\r\nup 4 1824\r\nup 5 600\r\ndown 0 0\r\ndown 1 0\r\ndown 2 200\r\ndown 3 400\r\ndown 4 800\r\ndown 5 50\r\nupLimit 0 204800\r\nupLimit 1 204800\r\nupLimit 2 204800\r\nupLimit 3 204800\r\nupLimit 4 204800\r\nupLimit 5 204800\r\ndownLimit 0 1048576\r\ndownLimit 1 1048576\r\ndownLimit 2 1048576\r\ndownLimit 3 1048576\r\ndownLimit 4 1048576\r\ndownLimit 5 1048576\r\nname 0 Laptop\r\nname 1 iPhone\r\nname 2 Laptop2\r\nname 3 iPhone2\r\nname 4 IoT_thing\r\nname 5 PC\r\nuBandwidth 0 0\r\nuBandwidth 1 0\r\nuBandwidth 2 0\r\nuBandwidth 3 0\r\nuBandwidth 4 0\r\nuBandwidth 5 0\r\nuStandard 0 0\r\nuStandard 1 0\r\nuStandard 2 0\r\nuStandard 3 2\r\nuStandard 4 2\r\nuStandard 5 0\r\ndevType 0 0\r\ndevType 1 0\r\ndevType 2 0\r\ndevType 3 0\r\ndevType 4 0\r\ndevType 5 0\r\npriTime 0 0\r\npriTime 1 0\r\npriTime 2 0\r\npriTime 3 0\r\npriTime 4 0\r\npriTime 5 0\r\nleaseTime 0 0\r\nleaseTime 1 0\r\nleaseTime 2 0\r\nleaseTime 3 0\r\nleaseTime 4 0\r\nleaseTime 5 0\r\ntotalVal 0 450\r\ntotalVal 1 5\r\ntotalVal 2 13\r\ntotalVal 3 956\r\ntotalVal 4 13\r\ntotalVal 5 53\r\ntotalUnit 0 2\r\ntotalUnit 1 2\r\ntotalUnit 2 2\r\ntotalUnit 3 2\r\ntotalUnit 4 2\r\ntotalUnit 5 2\r\ndhcpsEntry 0 0\r\ndhcpsEntry 1 0\r\ndhcpsEntry 2 0\r\ndhcpsEntry 3 0\r\ndhcpsEntry 4 0\r\ndhcpsEntry 5 0\r\nduration 0 0\r\nduration 1 0\r\nduration 2 0\r\nduration 3 73\r\nduration 4 5388\r\nduration 5 8559\r\ntxRate 0 0\r\ntxRate 1 0\r\ntxRate 2 0\r\ntxRate 3 156\r\ntxRate 4 130\r\ntxRate 5 0\r\nrxRate 0 0\r\nrxRate 1 0\r\nrxRate 2 0\r\nrxRate 3 130\r\nrxRate 4 173\r\nrxRate 5 0\r\naveRssi 0 0\r\naveRssi 1 0\r\naveRssi 2 0\r\naveRssi 3 33\r\naveRssi 4 46\r\naveRssi 5 0\r\nslEnable 0 0\r\nslEnable 1 0\r\nslEnable 2 0\r\nslEnable 3 0\r\nslEnable 4 0\r\nslEnable 5 0\r\npriScheStatus 0 0\r\npriScheStatus 1 0\r\npriScheStatus 2 0\r\npriScheStatus 3 0\r\npriScheStatus 4 0\r\npriScheStatus 5 0\r\nstart 0 0\r\nstart 1 0\r\nstart 2 0\r\nstart 3 0\r\nstart 4 0\r\nstart 5 0\r\nend 0 0\r\nend 1 0\r\nend 2 0\r\nend 3 0\r\nend 4 0\r\nend 5 0\r\nday 0 0\r\nday 1 0\r\nday 2 0\r\nday 3 0\r\nday 4 0\r\nday 5 0\r\nstartMin 0 0\r\nstartMin 1 0\r\nstartMin 2 0\r\nstartMin 3 0\r\nstartMin 4 0\r\nstartMin 5 0\r\nendMin 0 0\r\nendMin 1 0\r\nendMin 2 0\r\nendMin 3 0\r\nendMin 4 0\r\nendMin 5 0\r\nrate 0 0\r\nrate 1 0\r\nrate 2 0\r\nrate 3 156\r\nrate 4 173\r\nrate 5 0\r\ntxPkt 0 0\r\ntxPkt 1 0\r\ntxPkt 2 0\r\ntxPkt 3 42602\r\ntxPkt 4 119683\r\ntxPkt 5 0\r\nrxPkt 0 0\r\nrxPkt 1 0\r\nrxPkt 2 0\r\nrxPkt 3 6343\r\nrxPkt 4 275076\r\nrxPkt 5 0\r\nid 33|1,1,0\r\nuUnit 0\r\ncSsidPrefix\r\nuRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\nbBcastSsid 1\r\ncSsid TP-Link\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret admin\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 1\r\nbIsLocked 0\r\nbEnRtPIN 1\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1\r\nSecurityType 2\r\nbApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 1\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\nid 33|2,1,0\r\nuUnit 0\r\ncSsidPrefix\r\nuRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\nbBcastSsid 1\r\ncSsid TP-Link\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret admin\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 1\r\nbIsLocked 0\r\nbEnRtPIN 1\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1\r\nSecurityType 2\r\nbApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 1\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\nid 33|1,2,0\r\nuUnit 1\r\ncSsidPrefix Guest\r\nuRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 0\r\nbBcastSsid 1\r\ncSsid TP-Link_Guest\r\nbSecurityEnable 0\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 3\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 0\r\nSecurityType 1\r\nbApIsolated 1\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\nid 33|2,2,0\r\nuUnit 1\r\ncSsidPrefix Guest\r\nuRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 0\r\nbBcastSsid 1\r\ncSsid TP-Link_Guest_5G\r\nbSecurityEnable 0\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 3\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 0\r\nSecurityType 1\r\nbApIsolated 1\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\nid 33|1,9,0\r\nuUnit 9\r\ncSsidPrefix IoT\r\nuRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\nbBcastSsid 0\r\ncSsid TP-Link_IoT\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret 11100111\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1\r\nSecurityType 2\r\nbApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0\r\nid 33|2,9,0\r\nuUnit 9\r\ncSsidPrefix IoT\r\nuRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0\r\ncKeyVal 1\r\ncKeyVal 2\r\ncKeyVal 3\r\nuRadiusPort 1812\r\nuKeyType 0\r\nuDefaultKey 1\r\nbEnable 1\r\nbBcastSsid 0\r\ncSsid TP-Link_IoT\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 1\r\nuPSKEncryptType 3\r\ncRadiusSecret\r\ncPskSecret 11100111\r\nbSecCheck 0\r\nbEnabled 1\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nbEnRtPIN 0\r\nbWifiBtnRecEnable 1\r\nuVid 0\r\nbMumimo 0\r\nbMwdsEnable 0\r\nbLanAccess 1\r\nSecurityType 2\r\nbApIsolated 0\r\neffectiveTime 0\r\nuMaxUploadSpeed -1\r\nuMaxDownloadSpeed -1\r\nbwCtrlEnable 0\r\nenableBackup 0\r\nbTr069APEnable 0\r\nbTr069SSIDEnable 0'

        client = TplinkC80RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(status_response_text)
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

if __name__ == '__main__':
    main()