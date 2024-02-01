# TP-Link Router API
Python package for API access and management for TP-Link Router

[![Pypi](https://img.shields.io/pypi/v/tplinkrouterc6u)](https://pypi.org/project/tplinkrouterc6u/)
[![Downloads](https://static.pepy.tech/personalized-badge/tplinkrouterc6u?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/tplinkrouterc6u/)

See [Supported routers](#supports)

## Installation
`pip install tplinkrouterc6u`
`pip install -r requirements.txt`

## Dependencies
 - [requests](https://pypi.org/project/requests/)
 - [pycryptodome](https://pypi.org/project/pycryptodome/)

## Usage
Enter the host & credentials used to log in to your router management page. Username is admin by default. But you may pass username as third parameter

```python
from tplinkrouterc6u import TplinkRouter, Wifi
from logging import Logger

router = TplinkRouter('http://192.168.0.1', 'password')

# You may also pass username if it is different and a logger to log errors as
# TplinkRouter('http://192.168.0.1','password','admin2', Logger('test'))

# Get firmware info - returns Firmware
firmware = router.get_firmware()

# Get status info - returns Status
status = router.get_status()

# Turn ON guest wifi 2.5G
router.set_wifi(Wifi.WIFI_GUEST_2G, True)


# Get Address reservations, sort by ipaddr
reservations = router.get_ipv4_reservations()
reservations.sort(key=lambda a:a.ipaddr)
for res in reservations:
    print(f"{res.macaddr} {res.ipaddr:16s} {res.hostname:36} {'Permanent':12}")

# Get DHCP leases, sort by ipaddr
leases = router.get_ipv4_dhcp_leases()
leases.sort(key=lambda a:a.ipaddr)
for lease in leases:
    print(f"{lease.macaddr} {lease.ipaddr:16s} {lease.hostname:36} {lease.lease_time:12}")
```

The TP-Link Web Interface only supports upto 1 user logged in at a time (for security reasons, apparently).
So before action client authorize and after logout
To reduce authorization requests client allows to make several actions with one authorization

```python
from tplinkrouterc6u import TplinkRouter, Wifi

router = TplinkRouter('http://192.168.0.1', 'password', timeout)
router.single_request_mode = False  # make client use single authorization


try:
    if router.authorize():  # authorizing
        status = router.get_status()
        if not status.guest_2g_enable:  # check if guest 2.4G wifi is disable
            router.set_wifi(Wifi.WIFI_GUEST_2G, True)  # turn on guest 2.4G wifi
        finally:
            router.logout()  # always logout as TP-Link Web Interface only supports upto 1 user logged
```

## Functions
| Function | Args | Description | Return |
|--|--|--|--|
| get_firmware |  | Gets firmware info about the router | [Firmware](#firmware) |
| get_status |  | Gets status about the router info including wifi statuses and wifi clients info | [Status](#status) |
| get_full_info |  | Gets firmware and status info | tuple[[Firmware](#firmware),[Status](#status)] |
| get_ipv4_status | | Gets WAN and LAN IPv4 status info, gateway, DNS, netmask | [IPv4Status](#IPv4Status) |
| get_ipv4_reservations| | Gets IPv4 reserved addresses (static) | [[IPv4Reservation]](#IPv4Reservation) |
| get_ipv4_dhcp_leases | | Gets IPv4 addresses assigned via DHCP | [[IPv4DHCPLease]](#IPv4DHCPLease) | 
| set_wifi | wifi: [Wifi](#wifi), enable: bool | Allow to turn on/of 4 wifi networks |  |
| reboot |  | reboot router |
| authorize |  | authorize for actions |
| logout |  | logout after all is done |
| query | query, operation='operation=read' | execute cgi-bin query | dictionary of result or None |

## Dataclass
### <a id="firmware">Firmware</a>
| Field | Description | Type |
| --- |----|----|
| hardware_version | Returns like - Archer C6U | str |
| model | Returns like - Archer C6U v1.0 | str |
| firmware_version | Returns like - 1.1.3 Build 3425243 | str |

### <a id="status">Status</a>
| Field | Description | Type |
|---|---|---|
| wan_macaddr | router wan mac address | str, None |
| wan_macaddress | router wan mac address | macaddress.EUI48, None |
| lan_macaddr | router lan mac address | str, None |
| lan_macaddress | router lan mac address | macaddress.EUI48, None |
| wan_ipv4_addr | router wan ipv4 address | str, None |
| wan_ipv4_address | router wan ipv4 address | ipaddress.IPv4Address, None |
| lan_ipv4_addr | router lan ipv4 address | str, None |
| lan_ipv4_address | router lan ipv4 address | ipaddress.IPv4Address, None |
| wan_ipv4_gateway | router wan ipv4 gateway | str, None |
| wan_ipv4_gateway_address | router wan ipv4 gateway address | ipaddress.IPv4Address, None |
| wired_total | Total amount of wired clients | int |
| wifi_clients_total | Total amount of main wifi clients | int |
| guest_clients_total | Total amount of guest wifi clients | int |
| clients_total | Total amount of all connected clients | int |
| guest_2g_enable | Is guest wifi 2.4G enabled | bool |
| guest_5g_enable | Is guest wifi 5G enabled | bool |
| iot_2g_enable | Is IoT wifi 2.4G enabled | bool, None |
| iot_5g_enable | Is IoT wifi 5G enabled | bool, None |
| wifi_2g_enable | Is main wifi 2.4G enabled | bool |
| wifi_5g_enable | Is main wifi 5G enabled | bool |
| wan_ipv4_uptime | Internet Uptime | int, None |
| mem_usage | Memory usage | float, None |
| cpu_usage | CPU usage | float, None |
| devices | List of all wifi clients | list[[Device](#device)] |

### <a id="device">Device</a>
| Field | Description | Type |
| --- |---|---|
| type | client connection type (2.4G or 5G, guest wifi or main wifi) | [Wifi](#wifi) |
| macaddr | client mac address | str |
| macaddress | client mac address | macaddress |
| ipaddr | client ip address | str |
| ipaddress | client ip address | ipaddress |
| hostname | client hostname | str |

### <a id="IPv4Reservation">IPv4Reservation</a>
| Field | Description | Type |
| --- |---|---|
| macaddr | client mac address | str |
| macaddress| client mac address | macaddress |
| ipaddr | client ip address | str |
| ipaddress | client ip address | ipaddress |
| hostname | client hostname | str |
| enabled | enabled | bool |

### <a id="IPv4DHCPLease">IPv4DHCPLease</a>
| Field | Description | Type |
| --- |---|---|
| macaddr | client mac address | str |
| macaddress | client mac address | macaddress |
| ipaddr | client ip address | str |
| ipaddress | client ip address | ipaddress |
| hostname | client hostname | str |
| lease_time | ip address lease time | str |

### <a id="IPv4Status">IPv4Status</a>
| Field | Description | Type |
| --- |---|---|
| wan_macaddr | router mac address | str |
| wan_macaddress | router mac address | macaddress |
| wan_ipv4_ipaddr | router mac address | str |
| wan_ipv4_ipaddress | router mac address | ipaddress |
| wan_ipv4_gateway | router WAN gateway IP address | str |
| wan_ipv4_gateway_address | router WAN gateway IP address | ipaddress |
| wan_ipv4_conntype | router connection type | str |
| wan_ipv4_netmask | router WAN gateway IP netmask | str |
| wan_ipv4_netmask_address | router WAN gateway IP netmask | ipaddress |
| wan_ipv4_pridns | router primary dns server | str |
| wan_ipv4_pridns_address | router primary dns server | ipaddress |
| wan_ipv4_snddns | router secondary dns server | str |
| wan_ipv4_snddns_address | router secondary dns server | ipaddress |
| lan_macaddr | router mac address | str |
| lan_macaddress | router mac address | macaddress |
| lan_ipv4_ipaddr | router LAN IP address | str |
| lan_ipv4_ipaddress | router LAN IP address | ipaddress |
| lan_ipv4_dhcp_enable | router LAN DHCP enabled | bool |
| lan_ipv4_netmask | router LAN gateway IP netmask | str |
| lan_ipv4_netmask_address | router LAN gateway IP netmask | ipaddress |
| remote | router remote | bool |

## Enum
### <a id="wifi">Wifi</a>
- Wifi.WIFI_2G - main wifi 2.4G
- Wifi.WIFI_5G - main wifi 5G
- Wifi.WIFI_GUEST_2G - guest wifi 2.4G
- Wifi.WIFI_GUEST_5G - guest wifi 5G
- Wifi.WIFI_IOT_2G - IoT wifi 2.4G
- Wifi.WIFI_IOT_5G - IoT wifi 5G

## <a id="supports">Supported routers</a>
### Fully tested Hardware Versions
- Archer A7 V5
- Archer AX10 v1.0
- Archer AX20 v1.0
- Archer AX21 v1.20
- Archer AX50 v1.0
- Archer AX55 V1.60
- Archer AX73 V1
- Archer AX3000 V1
- Archer AX6000 V1
- Archer AX11000 V1
- Archer C6 v2.0
- Archer C6 v3.0
- Archer C6U v1.0
- Archer C7 v5.0
- TL-WA3001 v1.0

### Not fully tested Hardware Versions
- AD7200 V2
- Archer A6 (V2 and V3)
- Archer A9 V6
- Archer A10 (V1 and V2)
- Archer A20 (V1, V3)
- Archer C7 V4
- Archer C8 (V3 and V4)
- Archer C9 (V4 and V5)
- Archer C59 V2
- Archer C90 V6
- Archer C900 V1
- Archer C1200 V3 (V2 - should work, but not have been tested)
- Archer C1900 V2
- Archer C2300 (V1, V2)
- Archer C4000 (V2 and V3)
- Archer C5400 V2
- Archer C5400X V1
- TL-WR1043N V5

Please let me know if you have tested integration with one of this or other model. Open an issue with info about router's model, hardware and firmware versions.

## Local Development

- Download this repository.
- Run `pip install -e path/to/repo`.
- Make changes to files within the `tplinkrouter6u` directory.
- Exercise the changes following the "Usage" section above.

The sanity check test.py illustrates a few tests and runs through a list of queries in queries.txt creating logs of the results of each query in the logs folder. This can be used to capture the dictionary output of all cgi-bin form submissions.

## Thanks To
 - [EncryptionWrapper for TP-Link Archer C6U](https://github.com/ericpignet/home-assistant-tplink_router/pull/42/files) by [@Singleton-95](https://github.com/Singleton-95)
