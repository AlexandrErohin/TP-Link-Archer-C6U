from unittest import main, TestCase
from ipaddress import IPv4Address
from macaddress import EUI48
from tplinkrouterc6u.common.dataclass import Firmware, Status, Device
from tplinkrouterc6u.common.dataclass import IPv4Status, IPv4Reservation, IPv4DHCPLease
from tplinkrouterc6u import Connection, ClientException
from tplinkrouterc6u.client.re330 import TplinkRE330Router


IPV4_STATUS_RESPONSE = ('00000\r\nid 1|1,0,0\r\noldAuthKey \r\nsetWzd 1\r\nmode 3\r\nlogLevel 3\r\nfastpath 1\r\n'
                        'mac 0 00-00-00-00-00-01\r\nmac 1 00-00-00-00-00-02\r\nauthKey keykeykey\r\nid 4|1,0,0\r\n'
                        'ip 2.2.2.2\r\nmask 255.255.255.0\r\ngateway 3.3.3.3\r\ndns 0 1.1.1.1\r\n'
                        'dns 1 8.8.8.8\r\nmode 0\r\nid 8|1,0,0\r\nmode 2\r\npoolStart 192.168.1.100\r\n'
                        'poolEnd 192.168.1.199\r\n'
                        'leaseTime 120\r\ndns 0 0.0.0.0\r\ndns 1 0.0.0.0\r\ngateway 0.0.0.0\r\nhostName \r\n'
                        'id 22|1,0,0\r\nenable 1\r\nwirelessWanNoUsed 0\r\nlinkMode 0\r\nlinkType 0\r\nid 23|1,0,0\r\n'
                        'ip 4.4.4.4\r\nmask 255.255.252.0\r\ngateway 5.5.5.5\r\ndns 0 1.1.1.1\r\ndns 1 8.8.8.8\r\n'
                        'status 1\r\ncode 0\r\nupTime 0\r\ninPkts 0\r\ninOctets 0\r\noutPkts 0\r\noutOctets 0\r\n'
                        'inRates 0\r\noutRates 0\r\ndualMode 0\r\ndualIp 0.0.0.0\r\ndualMask 0.0.0.0\r\n'
                        'dualGateway 0.0.0.0\r\ndualDns 0 0.0.0.0\r\ndualDns 1 0.0.0.0\r\ndualCode 0\r\ndualStatus 0')

STATUS_RESPONSE_TEXT = ('00000\r\nid 1|1,0,0\r\noldAuthKey \r\nsetWzd 1\r\nmode 3\r\nlogLevel 3\r\nfastpath 1\r\n'
                        'mac 0 00-00-00-00-00-01\r\nmac 1 00-00-00-00-00-02\r\nauthKey keykeykey\r\nid 4|1,0,0\r\n'
                        'ip 2.2.2.2\r\nmask 255.255.255.0\r\ngateway 3.3.3.3\r\ndns 0 1.1.1.1\r\ndns 1 8.8.8.8\r\n'
                        'mode 0\r\nid 23|1,0,0\r\nip 4.4.4.4\r\nmask 255.255.255.0\r\ngateway 5.5.5.5\r\n'
                        'dns 0 1.1.1.1\r\ndns 1 8.8.8.8\r\nstatus 1\r\ncode 0\r\nupTime 0\r\ninPkts 0\r\ninOctets 0\r\n'
                        'outPkts 0\r\noutOctets 0\r\ninRates 0\r\noutRates 0\r\ndualMode 0\r\ndualIp 0.0.0.0\r\n'
                        'dualMask 0.0.0.0\r\ndualGateway 0.0.0.0\r\ndualDns 0 0.0.0.0\r\ndualDns 1 0.0.0.0\r\n'
                        'dualCode 0\r\ndualStatus 0\r\nid 13|1,0,0\r\nip 0 10.10.10.10\r\nip 1 11.11.11.11\r\n'
                        'ip 2 0.0.0.0\r\nip 3 0.0.0.0\r\nip 4 0.0.0.0\r\nip 5 0.0.0.0\r\nmac 0 00-00-00-00-00-03\r\n'
                        'mac 1 00-00-00-00-00-04\r\nmac 2 00-00-00-00-00-00\r\nmac 3 00-00-00-00-00-00\r\n'
                        'mac 4 00-00-00-00-00-00\r\nmac 5 00-00-00-00-00-00\r\n'
                        'reserved 0 \r\nreserved 1 \r\nreserved 2 \r\nreserved 3 \r\nreserved 4 \r\nreserved 5 \r\n'
                        'bindEntry 0 0\r\nbindEntry 1 0\r\nbindEntry 2 0\r\nbindEntry 3 0\r\nbindEntry 4 0\r\n'
                        'bindEntry 5 0\r\nstaMgtEntry 0 0\r\nstaMgtEntry 1 0\r\nstaMgtEntry 2 0\r\nstaMgtEntry 3 0\r\n'
                        'staMgtEntry 4 0\r\nstaMgtEntry 5 0\r\ntype 0 3\r\ntype 1 1\r\ntype 2 0\r\ntype 3 0\r\n'
                        'type 4 0\r\ntype 5 0\r\nonline 0 1\r\nonline 1 1\r\nonline 2 0\r\nonline 3 0\r\nonline 4 0\r\n'
                        'online 5 0\r\nname 0 ANONYMOUS\r\nname 1 BANANA-12\r\nname 2 \r\nname 3 \r\nname 4 \r\n'
                        'name 5 \r\nDevType 0 OTHER\r\nDevType 1 OTHER\r\nDevType 2 \r\nDevType 3 \r\nDevType 4 \r\n'
                        'DevType 5 \r\nid 33|1,1,0\r\nuUnit 0\r\ncSsidPrefix \r\nuRadiusIp 0.0.0.0\r\n'
                        'uRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\nuKeyLength 1 0\r\n'
                        'uKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0 \r\ncKeyVal 1 \r\ncKeyVal 2 \r\ncKeyVal 3 \r\n'
                        'uRadiusPort 1812\r\nuKeyType 1\r\nuDefaultKey 1\r\nbEnable 1\r\nbBcastSsid 1\r\n'
                        'cSsid SuperWifi\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3\r\nuRadiusSecOpt 3\r\n'
                        'uPSKSecOpt 2\r\nuRadiusEncryptType 4\r\nuPSKEncryptType 3\r\ncRadiusSecret \r\n'
                        'cPskSecret YouThoughtIdForgetMyKey?\r\nbSecCheck 0\r\nbEnabled 1\r\nbPinEnabled 0\r\n'
                        'cUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0\r\nid 33|2,1,0\r\nuUnit 0\r\ncSsidPrefix \r\n'
                        'uRadiusIp 0.0.0.0\r\nuRadiusGKUpdateIntvl 0\r\nuPskGKUpdateIntvl 0\r\nuKeyLength 0 0\r\n'
                        'uKeyLength 1 0\r\nuKeyLength 2 0\r\nuKeyLength 3 0\r\ncKeyVal 0 \r\ncKeyVal 1 \r\n'
                        'cKeyVal 2 \r\ncKeyVal 3 \r\nuRadiusPort 1812\r\nuKeyType 1\r\nuDefaultKey 1\r\nbEnable 1\r\n'
                        'bBcastSsid 1\r\ncSsid SuperWifi\r\nbSecurityEnable 1\r\nuAuthType 3\r\nuWEPSecOpt 3\r\n'
                        'uRadiusSecOpt 3\r\nuPSKSecOpt 2\r\nuRadiusEncryptType 4\r\nuPSKEncryptType 3\r\n'
                        'cRadiusSecret \r\ncPskSecret YouThoughtIdForgetMyKey?\r\nbSecCheck 0\r\n'
                        'bEnabled 1\r\nbPinEnabled 0\r\ncUsrPIN 11100111\r\nbConfigured 0\r\nbIsLocked 0')


class ResponseMock():
    def __init__(self, text, status_code=0):
        self.text = text
        self.status_code = status_code


class TplinkRE330RouterTest(TplinkRE330Router):
    response = ''

    def _init_session(self) -> None:
        pass

    def request(self, code: int, asyn: int, use_token: bool = False, data: str = None) -> dict | None:

        # Responses
        if code == 2 and (asyn == 0 or asyn == 1):
            if use_token is False:
                if data == '50|1,0,0':
                    # Supports
                    return ResponseMock(self.response, 200)
                else:
                    # Authorization
                    return ResponseMock('blabla\r\nblabla\r\nblabla\r\nauthinfo1\r\nauthinfo2')
            elif use_token is True:
                return ResponseMock(self.response)
        if code == 7 and asyn == 1:
            if use_token is False:
                # Authorization
                return ResponseMock('00007\r\n00004\r\n00002\r\n'
                                    'BC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E'
                                    '9D3DE83FE70C2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3\r\n'
                                    '12345656\r\n00000')
            elif use_token is True:
                return ResponseMock('00000')
        elif code == 16 and asyn == 0:
            if use_token is False:
                # Authorization
                return ResponseMock('00000\r\n010001\r\nBC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E'
                                    '9D3DE83FE70C2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3\r\n12345656')
            elif use_token is True:
                # Authorization
                return ResponseMock('00000')
        elif code == 7 and asyn == 0:
            return ResponseMock('00000')

        raise ClientException()

    def set_encrypted_response(self, response_text) -> None:
        self.response = self._encrypt_body(response_text).split('data=')[1]


class TestTPLinkClient(TestCase):

    def test_supports(self) -> None:
        response = ('00000\r\nid 50|1,0,0\r\ncurrentLanguage\r\n'
                    'languageList bg_BG,cs_CZ,de_DE,en_US,es_ES,es_LA,fr_FR,hu_HU,it_IT,ja_JP,ko_KR,nl_NL,pl_PL,pt_BR,'
                    'pt_PT,ro_RO,ru_RU,sk_SK,tr_TR,uk_UA,vi_VN,zh_TW\r\nsetByUser 0')

        client = TplinkRE330RouterTest('', '')
        client.response = response
        supports = client.supports()
        self.assertTrue(supports)

    def test_authorize(self) -> None:
        client = TplinkRE330RouterTest('', '')
        client.authorize()

        encryption = client._encryption
        self.assertEqual(encryption.ee_rsa, '010001')
        self.assertEqual(encryption.nn_rsa, 'BC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E9D3DE83FE70C'
                                            '2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3')
        self.assertEqual(encryption.seq, '12345656')

    def test_get_firmware(self) -> None:
        response = ('00000\r\nid 0|1,0,0\r\nfullName TP-Link%20Wireless%20Extender%20RE330\r\nfacturer TP-Link\r\n'
                    'modelName RE330\r\nmodelVer 1\r\nsoftVer 1.0.23%20Build%20230418%20Rel.60395n\r\n'
                    'hardVer %20RE330%201.0\r\nprodId 0x3300001\r\ncloudShouldActive 1\r\ncountryId 0x0\r\n'
                    'specialId 0x5545\r\ncountryCode 0x4544\r\nmainVer 0x5a010017\r\nminorVer 0x1\r\noemId 0x1\r\n'
                    'deviceId 8002A1F018FA0C879DB62FA981FB0D1D231D490F\r\n'
                    'hardwareId 5E055ADC85F0800C6C3044E5A3180E2A\r\nfirmwareId FFFFFFFFFFFFFFFFFFFF033001004555\r\n'
                    'oem_id B30DDAF6C31C08B9C50A48B0B9168003\r\nfacturerType 0')

        client = TplinkRE330RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(response)

        firmware = client.get_firmware()

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, ' RE330 1.0')
        self.assertEqual(firmware.model, 'RE330')
        self.assertEqual(firmware.firmware_version, '1.0.23 Build 230418 Rel.60395n')

    def test_get_ipv4_status(self) -> None:

        client = TplinkRE330RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(IPV4_STATUS_RESPONSE)

        ipv4_status: IPv4Status = client.get_ipv4_status()

        self.assertIsInstance(ipv4_status, IPv4Status)
        self.assertEqual(ipv4_status.wan_macaddress, EUI48('00-00-00-00-00-02'))
        self.assertEqual(ipv4_status._wan_ipv4_ipaddr, IPv4Address('4.4.4.4'))
        self.assertEqual(ipv4_status._wan_ipv4_gateway, IPv4Address('5.5.5.5'))
        self.assertEqual(ipv4_status._wan_ipv4_conntype, 'Dynamic IP')
        self.assertEqual(ipv4_status._wan_ipv4_netmask, IPv4Address('255.255.252.0'))
        self.assertEqual(ipv4_status._wan_ipv4_pridns, IPv4Address('1.1.1.1'))
        self.assertEqual(ipv4_status._wan_ipv4_snddns, IPv4Address('8.8.8.8'))
        self.assertEqual(ipv4_status._lan_macaddr, EUI48('00-00-00-00-00-01'))
        self.assertEqual(ipv4_status._lan_ipv4_ipaddr, IPv4Address('2.2.2.2'))
        self.assertEqual(ipv4_status.lan_ipv4_dhcp_enable, False)
        self.assertEqual(ipv4_status._lan_ipv4_netmask, IPv4Address('255.255.255.0'))

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

        client = TplinkRE330RouterTest('', '')
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

        client = TplinkRE330RouterTest('', '')
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

    def test_get_status(self) -> None:
        client = TplinkRE330RouterTest('', '')
        client.authorize()

        client.set_encrypted_response(STATUS_RESPONSE_TEXT)
        status = client.get_status()

        self.assertIsInstance(status, Status)
        self.assertEqual(status.wan_macaddr, '00-00-00-00-00-02')
        self.assertIsInstance(status.wan_macaddress, EUI48)
        self.assertEqual(status.lan_macaddr, '00-00-00-00-00-01')
        self.assertIsInstance(status.lan_macaddress, EUI48)
        self.assertEqual(status.wan_ipv4_addr, '4.4.4.4')
        self.assertIsInstance(status.lan_ipv4_address, IPv4Address)
        self.assertEqual(status.lan_ipv4_addr, '2.2.2.2')
        self.assertEqual(status.wan_ipv4_gateway, '5.5.5.5')
        self.assertIsInstance(status.wan_ipv4_address, IPv4Address)
        self.assertEqual(status.wired_total, 0)
        self.assertEqual(status.wifi_clients_total, 2)
        self.assertEqual(status.guest_clients_total, 0)
        self.assertEqual(status.clients_total, 2)
        self.assertEqual(status.iot_clients_total, 0)
        self.assertFalse(status.guest_2g_enable)
        self.assertFalse(status.guest_5g_enable)
        self.assertFalse(status.iot_2g_enable)
        self.assertFalse(status.iot_5g_enable)
        self.assertTrue(status.wifi_2g_enable)
        self.assertTrue(status.wifi_5g_enable)
        self.assertEqual(status.wan_ipv4_uptime, 0)
        self.assertEqual(status.mem_usage, None)
        self.assertEqual(status.cpu_usage, None)
        self.assertEqual(len(status.devices), 2)

        device = status.devices[0]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.HOST_5G)
        self.assertEqual(device.macaddr, '00-00-00-00-00-03')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '10.10.10.10')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'ANONYMOUS')
        self.assertEqual(device.up_speed, 0)
        self.assertEqual(device.down_speed, 0)
        self.assertEqual(device.active, True)

        device = status.devices[1]
        self.assertIsInstance(device, Device)
        self.assertEqual(device.type, Connection.HOST_2G)
        self.assertEqual(device.macaddr, '00-00-00-00-00-04')
        self.assertIsInstance(device.macaddress, EUI48)
        self.assertEqual(device.ipaddr, '11.11.11.11')
        self.assertIsInstance(device.ipaddress, IPv4Address)
        self.assertEqual(device.hostname, 'BANANA-12')
        self.assertEqual(device.up_speed, 0)
        self.assertEqual(device.down_speed, 0)
        self.assertEqual(device.active, True)

    def test_get_led_status(self) -> None:
        client = TplinkRE330RouterTest('', '')
        client.authorize()

        client.set_encrypted_response('00000\r\nid 112|1,0,0\r\nenable 1')
        led_status = client.get_led_status()
        self.assertEqual(led_status, True)

        client.set_encrypted_response('00000\r\nid 112|1,0,0\r\nenable 0')
        led_status = client.get_led_status()
        self.assertEqual(led_status, False)


if __name__ == '__main__':
    main()
