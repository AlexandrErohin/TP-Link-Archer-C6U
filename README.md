# TP-Link Router API
Python package for API access and management for TP-Link Routers. See [Supported routers](#supports)

[![Pypi](https://img.shields.io/pypi/v/tplinkrouterc6u)](https://pypi.org/project/tplinkrouterc6u/)
[![Downloads](https://static.pepy.tech/personalized-badge/tplinkrouterc6u?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/tplinkrouterc6u/)
![Python versions](https://img.shields.io/pypi/pyversions/tplinkrouterc6u)

## Installation
`pip install tplinkrouterc6u`

## Dependencies
 - [requests](https://pypi.org/project/requests/)
 - [pycryptodome](https://pypi.org/project/pycryptodome/)

## Usage
Enter the host & credentials used to log in to your router management page. Username is admin by default. But you may pass username as third parameter

```python
from tplinkrouterc6u import (
    TplinkRouterProvider, 
    TplinkRouter,
    TplinkC1200Router,
    TPLinkMRClient,
    TPLinkDecoClient,
    Wifi
)
from logging import Logger

router = TplinkRouterProvider.get_client('http://192.168.0.1', 'password')
# You may use client directly like
# router = TplinkRouter('http://192.168.0.1', 'password')
# You may also pass username if it is different and a logger to log errors as
# router = TplinkRouter('http://192.168.0.1','password','admin2', Logger('test'))
# If you have the TP-link C1200 V2 or similar, you can use the TplinkC1200Router class instead of the TplinkRouter class.
# Remember that the password for this router is different, here you need to use the web encrypted password.
# To get web encrypted password, read Web Encrypted Password section
# router = TplinkC1200Router('http://192.168.0.1','WebEncryptedPassword', Logger('test'))

try:
    router.authorize()  # authorizing
    # Get firmware info - returns Firmware
    firmware = router.get_firmware()

    # Get status info - returns Status
    status = router.get_status()
    if not status.guest_2g_enable:  # check if guest 2.4G wifi is disable
        router.set_wifi(Wifi.WIFI_GUEST_2G, True)  # turn on guest 2.4G wifi

    # Get Address reservations, sort by ipaddr
    reservations = router.get_ipv4_reservations()
    reservations.sort(key=lambda a: a.ipaddr)
    for res in reservations:
        print(f"{res.macaddr} {res.ipaddr:16s} {res.hostname:36} {'Permanent':12}")

    # Get DHCP leases, sort by ipaddr
    leases = router.get_ipv4_dhcp_leases()
    leases.sort(key=lambda a: a.ipaddr)
    for lease in leases:
        print(f"{lease.macaddr} {lease.ipaddr:16s} {lease.hostname:36} {lease.lease_time:12}")
finally:
    router.logout()  # always logout as TP-Link Web Interface only supports upto 1 user logged
```

The TP-Link Web Interface only supports upto 1 user logged in at a time (for security reasons, apparently).
So before action you need to authorize and after logout

### <a id="encrypted_pass">Web Encrypted Password</a>
If you got exception - `You need to use web encrypted password instead. Check the documentation!`
or you have TP-link C1200 V2 or similar router you need to get web encrypted password by these actions:
1. Go to the login page of your router. (default: 192.168.0.1).
2. Type in the password you use to login into the password field.
3. Click somewhere else on the page so that the password field is not selected anymore.
4. Open the JavaScript console of your browser (usually by pressing F12 and then clicking on "Console").
5. Type `document.getElementById("login-password").value;`
6. Copy the returned value as password and use it.

## Functions
| Function | Args | Description | Return |
|--|--|--|--|
| get_firmware |  | Gets firmware info about the router | [Firmware](#firmware) |
| get_status |  | Gets status about the router info including wifi statuses and wifi clients info | [Status](#status) |
| get_ipv4_status |  | Gets WAN and LAN IPv4 status info, gateway, DNS, netmask | [IPv4Status](#IPv4Status) |
| get_ipv4_reservations |  | Gets IPv4 reserved addresses (static) | [[IPv4Reservation]](#IPv4Reservation) |
| get_ipv4_dhcp_leases |  | Gets IPv4 addresses assigned via DHCP | [[IPv4DHCPLease]](#IPv4DHCPLease) | 
| set_wifi | wifi: [Wifi](#wifi), enable: bool | Allow to turn on/of 4 wifi networks |  |
| send_sms | phone_number: str, message: str | Send sms for LTE routers |  |
| reboot |  | reboot router |
| authorize |  | authorize for actions |
| logout |  | logout after all is done |

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
| lan_macaddr | router lan mac address | str |
| lan_macaddress | router lan mac address | macaddress.EUI48 |
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
| guest_5g_enable | Is guest wifi 5G enabled | bool, None |
| guest_6g_enable | Is guest wifi 6G enabled | bool, None |
| iot_2g_enable | Is IoT wifi 2.4G enabled | bool, None |
| iot_5g_enable | Is IoT wifi 5G enabled | bool, None |
| iot_6g_enable | Is IoT wifi 6G enabled | bool, None |
| wifi_2g_enable | Is main wifi 2.4G enabled | bool |
| wifi_5g_enable | Is main wifi 5G enabled | bool, None |
| wifi_6g_enable | Is main wifi 6G enabled | bool, None |
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
| packets_sent | total packets sent | int, None |
| packets_received | total packets received | int, None |

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
| wan_ipv4_ipaddr | router mac address | str, None |
| wan_ipv4_ipaddress | router mac address | ipaddress.IPv4Address, None |
| wan_ipv4_gateway | router WAN gateway IP address | str, None |
| wan_ipv4_gateway_address | router WAN gateway IP address | ipaddress.IPv4Address, None |
| wan_ipv4_conntype | router connection type | str |
| wan_ipv4_netmask | router WAN gateway IP netmask | str, None |
| wan_ipv4_netmask_address | router WAN gateway IP netmask | ipaddress.IPv4Address, None |
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
| remote | router remote | bool, None |

## Enum
### <a id="wifi">Wifi</a>
- Wifi.WIFI_2G - main wifi 2.4G
- Wifi.WIFI_5G - main wifi 5G
- Wifi.WIFI_6G - main wifi 5G
- Wifi.WIFI_GUEST_2G - guest wifi 2.4G
- Wifi.WIFI_GUEST_5G - guest wifi 5G
- Wifi.WIFI_GUEST_6G - guest wifi 5G
- Wifi.WIFI_IOT_2G - IoT wifi 2.4G
- Wifi.WIFI_IOT_5G - IoT wifi 5G
- Wifi.WIFI_IOT_6G - IoT wifi 6G

## <a id="supports">Supported routers</a>
### Fully tested Hardware Versions
- Archer A7 V5
- Archer AX10 v1.0
- Archer AX20 v1.0
- Archer AX21 v1.20
- Archer AX50 v1.0
- Archer AX55 v1.0
- Archer AX55 V1.60
- Archer AX72 V1
- Archer AX73 V1
- Archer AX75 V1
- Archer AXE75 V1
- Archer AX3000 V1
- Archer AX6000 V1
- Archer AX11000 V1
- Archer C1200 v2.0 (You need to use [web encrypted password](#encrypted_pass))
- Archer C6 v2.0
- Archer C6 v3.0
- Archer C6U v1.0
- Archer C7 v5.0
- Archer MR200 v5
- Archer MR200 v5.3
- Archer MR600 v1
- Archer VR900v
- Deco M4 2.0
- Deco M4R 2.0
- TL-WA3001 v1.0
- TL-MR105
- TL-MR6400 v5

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
- Archer C1200 V3
- Archer C1900 V2
- Archer C2300 (V1, V2)
- Archer C4000 (V2 and V3)
- Archer C5400 V2
- Archer C5400X V1
- TD-W9960 v1
- TL-WR1043N V5

Please let me know if you have tested integration with one of this or other model. Open an issue with info about router's model, hardware and firmware versions.

## <a id="add_support">Adding Support For More Models</a>
Guidelines [CONTRIBUTING.md](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/blob/master/CONTRIBUTING.md)

## Local Development

- Download this repository.
- Run `pip install -e path/to/repo`.
- Make changes to files within the `tplinkrouter6u` directory.
- Exercise the changes following the "Usage" section above.

The sanity check test.py illustrates a few tests and runs through a list of queries in queries.txt creating logs of the results of each query in the logs folder. This can be used to capture the dictionary output of all cgi-bin form submissions.

### Run tests
- Run `python -m unittest discover ./test`

## Thanks To
 - [EncryptionWrapper for TP-Link Archer C6U](https://github.com/ericpignet/home-assistant-tplink_router/pull/42/files) by [@Singleton-95](https://github.com/Singleton-95)
 - [Encryption for TP-Link W9960](https://github.com/Electry/TPLink-W9960-APIClient) by [@Electry](https://github.com/Electry)
