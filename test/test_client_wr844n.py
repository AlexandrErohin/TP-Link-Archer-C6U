from ipaddress import IPv4Address
from unittest import TestCase, main

from macaddress import EUI48

from tplinkrouterc6u import Connection
from tplinkrouterc6u.client.wr844n import TplinkWR844NRouter
from tplinkrouterc6u.common.dataclass import Device, Firmware, Status
from tplinkrouterc6u.common.exception import ClientException


FIRMWARE_RESPONSE = ('00000\r\nid 0|1,0,0\r\nfullName 300Mbps%20Wi-Fi%20Router\r\nfacturer TP-Link\r\n'
                     'modelName TL-WR844N\r\nmodelVer 1.0\r\n'
                     'softVer 1.10.0%20Build%20211011%20Rel.66152n(4555)\r\n'
                     'hardVer TL-WR844N%201.0\r\nprodId 0x8440001')

STATUS_RESPONSE = ('00000\r\nid 1|1,0,0\r\nauthKey token\r\nreserved\r\nsetWzd 1\r\nmode 4\r\n'
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


class ResponseMock:
    def __init__(self, text, status_code=0):
        self.text = text
        self.status_code = status_code


class TplinkWR844NRouterTest(TplinkWR844NRouter):
    response = ''

    def request(self, code: int, asyn: int, use_token: bool = False, data: str = None) -> ResponseMock | None:
        if code == 2 and asyn == 1:
            if use_token is False:
                if data == '0|1,0,0':
                    return ResponseMock(FIRMWARE_RESPONSE, 200)
                return ResponseMock('blabla\r\nblabla\r\nblabla\r\nauthinfo1\r\nauthinfo2')
            return ResponseMock(self.response)
        if (code == 16 or code == 7) and asyn == 0:
            if use_token is False:
                return ResponseMock('00000\r\n010001\r\nBC97577E65233B3E1137C61091D64176C334E52AD78FFBDDABC826B685435E'
                                    '9D3DE83FE70C2AC62D6B13BD8EADA10B5623F9354DA0E99636A4F5519CA2DC2DC3\r\n12345656')
            return ResponseMock('00000')

        raise ClientException()


class TestTPLinkWR844NClient(TestCase):
    def test_supports(self) -> None:
        client = TplinkWR844NRouterTest('', '')

        self.assertTrue(client.supports())

    def test_get_firmware_handles_plaintext_response(self) -> None:
        client = TplinkWR844NRouterTest('', '')
        client.authorize()
        client.response = FIRMWARE_RESPONSE

        firmware = client.get_firmware()

        self.assertIsInstance(firmware, Firmware)
        self.assertEqual(firmware.hardware_version, 'TL-WR844N 1.0')
        self.assertEqual(firmware.model, 'TL-WR844N')
        self.assertEqual(firmware.firmware_version, '1.10.0 Build 211011 Rel.66152n(4555)')

    def test_get_status_uses_dhcp_client_block(self) -> None:
        client = TplinkWR844NRouterTest('http://192.168.0.68', '')
        client.authorize()
        client.response = STATUS_RESPONSE

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


if __name__ == '__main__':
    main()
