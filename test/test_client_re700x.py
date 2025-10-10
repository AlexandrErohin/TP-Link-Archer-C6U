from unittest import main, TestCase
from json import loads
from tplinkrouterc6u import (
    Status,
    ClientException,
    TplinkRe700XRouter,
)


class TestTPLinkClientRe700X(TestCase):
    def test_get_status(self) -> None:
        class TPLinkRouterTest(TplinkRe700XRouter):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if (
                    path == "admin/status?form=status_device"
                    and data == "operation=read"
                ):
                    return loads(
                        '{"success":true,"data":{"wired_dhcp":"1","wired_ip":"192.168.1.4","wired_type":"0"}}'
                    )["data"]
                elif path == "admin/status?form=ap_status" and data == "operation=read":
                    return loads(
                        """
                        {
                  "success": true,
                  "data": {
                    "wireless_2g_encryption": true,
                    "show2gFlag": true,
                    "phyconn": "connected",
                    "wireless_5g_enable": "on",
                    "internet_status": "connected",
                    "wireless_2g_enable": "on",
                    "wireless_5g_encryption": true,
                    "opMode": "0",
                    "show5gFlag": true,
                    "wirelessCount": 8,
                    "wirelessGrid": [
                      {
                        "mac": "7C-2C-67-D9-E9-14",
                        "type": "2.4GHz",
                        "name": "esp32c3-D9E914",
                        "conn_type": "wireless",
                        "rxrate": 108,
                        "txrate": 150,
                        "ipaddr": "192.168.1.52",
                        "ip": "192.168.1.52"
                      },
                      {
                        "mac": "26-96-9F-67-1E-C5",
                        "type": "5GHz",
                        "name": "Mac",
                        "conn_type": "wireless",
                        "rxrate": 648,
                        "txrate": 960,
                        "ipaddr": "192.168.1.55",
                        "ip": "192.168.1.55"
                      }
                    ]
                  }
                    }"""
                    )["data"]
                elif path == "admin/status?form=guest" and data == "operation=read":
                    return loads(
                        """
                        {
                  "success": true,
                  "data": [
                    {
                      "mac": "B0-4A-39-98-20-AD",
                      "type": "2.4GHz",
                      "name": "roborock-vacuum-a51",
                      "conn_type": "wireless",
                      "rxrate": 150,
                      "txrate": 150,
                      "ipaddr": "192.168.1.51",
                      "ip": "192.168.1.51"
                    },
                    {
                      "mac": "FC-3C-D7-2A-DE-10",
                      "type": "2.4GHz",
                      "name": "wlan0",
                      "conn_type": "wireless",
                      "rxrate": 52,
                      "txrate": 65,
                      "ipaddr": "192.168.1.54",
                      "ip": "192.168.1.54"
                    }
                  ]
                }"""
                    )["data"]
                elif path == "admin/extend?form=guest_settings":
                    return loads(
                        """
                        {"success":true,"data":{"enable_5g":"off","region_status":1,"hide_5g":"off","hide_2g":"off","show2gFlag":"true","mesh_enable":"off","password":"***","show5gFlag":"true","ap_support_mesh":"0","sync_status":"0","ssid_2g":"XYZ","sec":"wpa2/wpa3","ssid_5g":"TP-Link_Guest_5G","enable_2g":"on"}}"""
                    )["data"]
                raise ClientException()

        client = TPLinkRouterTest("", "")
        status = client.get_status()

        self.assertIsInstance(status, Status)
        # TODO check each field of status

    def test_get_ipv4_dhcp_leases(self) -> None:
        class TPLinkRouterTest(TplinkRe700XRouter):
            def request(
                self,
                path: str,
                data: str,
                ignore_response: bool = False,
                ignore_errors: bool = False,
            ) -> dict | None:
                if path == "admin/dhcps?form=client" and data == "operation=load":
                    return loads(
                        """
  {
  "success": true,
  "data": [
    {
      "leasetime": "00:00:38",
      "key": "0",
      "macaddr": "a8:46:74:46:14:f8",
      "ipaddr": "192.168.1.59",
      "name": "bedroom-ble"
    }
  ]
}
"""
                    )["data"]
                raise ClientException()

        client = TPLinkRouterTest("", "")
        status = client.get_ipv4_dhcp_leases()

        self.assertIsInstance(status, list)
        # TODO check each field of status


if __name__ == "__main__":
    main()
