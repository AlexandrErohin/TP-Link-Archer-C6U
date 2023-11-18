# TP-Link Router API
Python package for API access and router management of the TP-Link Archer C6U and Archer AX10

## Supports
- Archer C6U
- Archer AX10

## Installation
`pip install tplinkrouterc6u`

## Dependencies
 - [aiohttp](https://pypi.org/project/aiohttp/)
 - [pycryptodome](https://pypi.org/project/pycryptodome/)

## Usage
Enter your hostname/IP & credentials used to log in to your router management page. Username is admin by default. But you may pass username as third parameter

```python
import asyncio
from tplinkrouterc6u import TplinkRouter

router = TplinkRouter('hostname', 'password')

# You may also pass username if it is different and a logger to log errors as
# TplinkRouter('hostname','password','admin2', _LOGGER)

# Get firmware info - returns Firmware
firmware = asyncio.run(router.get_firmware())

# Get status info - returns Status
full_info = asyncio.run(router.get_status())

# Turn ON guest wifi 2.5G
asyncio.run(router.set_wifi(Wifi.WIFI_GUEST_2G, True))
```

The TP-Link Web Interface only supports upto 1 user logged in at a time (for security reasons, apparently).
So before action client authorize and after logout
To reduce authorization requests client allows to make several actions with one authorization

```python
import asyncio
from tplinkrouterc6u import TplinkRouter, Wifi

router = TplinkRouter('hostname', 'password')
router.single_request_mode = False  # make client use single authorization


async def tasks():
    try:
        if await router.authorize():  # authorizing
            status = await router.get_status()
            if not status.guest_2g_enable:  # check if guest 2.4G wifi is disable
                await router.set_wifi(Wifi.WIFI_GUEST_2G, True)  # turn on guest 2.4G wifi
    finally:
        await router.logout()  # always logout as TP-Link Web Interface only supports upto 1 user logged 

asyncio.run(tasks())
```

## Functions
| Function | Args | Description | Return |
|--|--|--|--|
| get_firmware |  | Gets firmware info about the router | [Firmware](#firmware) |
| get_status |  | Gets status about the router info including wifi statuses and wifi clients info | [Status](#status) |
| get_full_info |  | Gets firmware and status info | tuple[[Firmware](#firmware),[Status](#status)] |
| set_wifi | wifi: [Wifi](#wifi), enable: bool | Allow to turn on/of 4 wifi networks |  |
| reboot | reboot router |  |
| authorize | authorize for actions |  |
| logout | logout after all is done |  |

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
| wan_ipv4_uptime | Internet Uptime | int |
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

## Thanks To
 - [EncryptionWrapper for TP-Link Archer C6U](https://github.com/ericpignet/home-assistant-tplink_router/pull/42/files) by [@Singleton-95](https://github.com/Singleton-95)