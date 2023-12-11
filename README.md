# TP-Link Router API
Python package for API access and management for TP-Link Router

[![Pypi](https://img.shields.io/pypi/v/tplinkrouterc6u)](https://pypi.org/project/tplinkrouterc6u/)
[![Downloads](https://static.pepy.tech/personalized-badge/tplinkrouterc6u?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/tplinkrouterc6u/)

See [Supported routers](#supports)

## Installation
`pip install tplinkrouterc6u`

## Dependencies
 - [requests](https://pypi.org/project/requests/)
 - [pycryptodome](https://pypi.org/project/pycryptodome/)

## Usage
Enter the host & credentials used to log in to your router management page. Username is admin by default. But you may pass username as third parameter

```python
from tplinkrouterc6u import TplinkRouter, Wifi

router = TplinkRouter('http://192.168.0.1', 'password')

# You may also pass username if it is different and a logger to log errors as
# TplinkRouter('http://192.168.0.1','password','admin2', _LOGGER)

# Get firmware info - returns Firmware
firmware = router.get_firmware()

# Get status info - returns Status
full_info = router.get_status()

# Turn ON guest wifi 2.5G
router.set_wifi(Wifi.WIFI_GUEST_2G, True)
```

The TP-Link Web Interface only supports upto 1 user logged in at a time (for security reasons, apparently).
So before action client authorize and after logout
To reduce authorization requests client allows to make several actions with one authorization

```python
from tplinkrouterc6u import TplinkRouter, Wifi

router = TplinkRouter('http://192.168.0.1', 'password')
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
| set_wifi | wifi: [Wifi](#wifi), enable: bool | Allow to turn on/of 4 wifi networks |  |
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
| --- |---|---|
| macaddr | router mac address | str |
| wired_total | Total amount of wired clients | int |
| wifi_clients_total | Total amount of main wifi clients | int |
| guest_clients_total | Total amount of guest wifi clients | int |
| clients_total | Total amount of all connected clients | int |
| guest_2g_enable | Is guest wifi 2.4G enabled | bool |
| guest_5g_enable | Is guest wifi 5G enabled | bool |
| wifi_2g_enable | Is main wifi 2.4G enabled | bool |
| wifi_5g_enable | Is main wifi 5G enabled | bool |
| wan_ipv4_uptime | Internet Uptime | int, None |
| mem_usage | Memory usage | float |
| cpu_usage | CPU usage | float |
| devices | List of all wifi clients | list[[Device](#device)] |

### <a id="device">Device</a>
| Field | Description | Type |
| --- |---|---|
| type | client connection type (2.4G or 5G, guest wifi of main wifi) | [Wifi](#wifi) |
| macaddr | client mac address | str |
| ipaddr | client ip address | str |
| hostname | client hostname | str |

## Enum
### <a id="wifi">Wifi</a>
- Wifi.WIFI_2G - main wifi 2.4G
- Wifi.WIFI_5G - main wifi 5G
- Wifi.WIFI_GUEST_2G - guest wifi 2.4G
- Wifi.WIFI_GUEST_5G - guest wifi 5G


## <a id="supports">Supported routers</a>
### Fully tested Hardware Versions
- Archer AX10 v1.0
- Archer C6 v2.0
- Archer C6U v1.0

### Not fully tested Hardware Versions
- AD7200 V2
- Archer A6 (V2 and V3)
- Archer A7 V5
- Archer A9 V6
- Archer A10 (V1 and V2)
- Archer A20 (V1, V3)
- Archer AX50 V1
- Archer AX3000 V1
- Archer AX6000 V1
- Archer C6 V4
- Archer C7 (V4 and V5)
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

## Thanks To
 - [EncryptionWrapper for TP-Link Archer C6U](https://github.com/ericpignet/home-assistant-tplink_router/pull/42/files) by [@Singleton-95](https://github.com/Singleton-95)
