import os
import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)-8s %(message)s")
import macaddress
import ipaddress
from typing import TypeAlias
from tplinkrouterc6u import Wifi, TplinkRouterProvider
from tplinkrouterc6u.dataclass import Status, Device
from mac_vendor_lookup import MacLookup, BaseMacLookup
import pprint
import json
from pathlib import Path

BaseMacLookup.cache_path = "mac_lookup.txt"
maclookup = MacLookup()
try:
    print("fetching maclookup vendor database")
    if os.path.isfile("mac_lookup.txt"):
        maclookup.update_vendors("file://./mac_lookup.txt")
    else:
        maclookup.update_vendors()
except Exception as ex:
    pass


def lookup(mac):
    try:
        vendor = maclookup.lookup(str(mac))
    except:
        vendor = "Unknown"
    return vendor


# Test @property getters from Device dataclass
print("testing Device dataclass")


def get_device() -> Device:
    d = Device(Wifi.WIFI_2G, macaddress.EUI48("11-22-33-44-55-66"), ipaddress.IPv4Address("192.168.0.1"), "router")
    return d


d = get_device()
assert isinstance(d.macaddr, str), "Type of macaddr is not type str"
assert isinstance(d.macaddress, macaddress.EUI48), "macaddress is not type macaddress.EUI48"
assert isinstance(d.ipaddr, str), "Type of ipaddr is not type str"
assert isinstance(d.ipaddress, ipaddress.IPv4Address), "Type of ipaddress is not ipaddress.IPv4Address"

# Test typing from AlexandrErohin 
MAC_ADDR: TypeAlias = str
tracked: dict[MAC_ADDR, str] = {}
tracked[d.macaddr] = "This item is tracked"

# Test the Status dataclass
print("testing Status dataclass")


def get_status(device: d) -> Status:
    status = Status()
    status.devices = []
    status._wan_macaddr = macaddress.EUI48("11-22-33-44-55-66")
    status._lan_macaddr = macaddress.EUI48("11-22-33-44-55-66")
    status._wan_ipv4_addr = ipaddress.IPv4Address("192.168.0.1")
    status._lan_ipv4_addr = ipaddress.IPv4Address("192.168.0.1")
    status._wan_ipv4_gateway = ipaddress.IPv4Address("192.168.0.1")
    status.wan_ipv4_uptime = "1"
    status.mem_usage = 1.2
    status.cpu_usage = 0.9
    status.wired_total = 1
    status.wifi_clients_total = 1
    status.guest_clients_total = 1
    status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total
    status.guest_2g_enable = True
    status.guest_5g_enable = True
    status.iot_2g_enable = False
    status.iot_5g_enable = False
    status.wifi_2g_enable = True
    status.wifi_5g_enable = True
    status.devices.append(d)
    return status


s = get_status(d)
assert isinstance(s.wan_macaddr, str), "Type of macaddr is not type str"
assert isinstance(s.wan_macaddress, macaddress.EUI48), "macaddress is not type macaddress.EUI48"
assert isinstance(s.lan_ipv4_addr, str), "Type of ipaddr is not type str"
assert isinstance(s.lan_ipv4_address, ipaddress.IPv4Address), "Type of ipaddress is not ipaddress.IPv4Address"

# Connect to router
print("Connecting to router")
password = input("password: ")
router = TplinkRouterProvider.get_client('http://192.168.0.1', password, logger=logging)
router.authorize()

# Get firmware info - returns Firmware
firmware = router.get_firmware()
print(f"firmware version: {firmware.firmware_version}")
print(f"hardware version: {firmware.hardware_version}")

# Get status info - returns Status
status = router.get_status()
print(f"WAN MAC: {status.wan_macaddr}")
print(f"WAN IPV4: {status.wan_ipv4_addr}")
print(f"WAN GATEWAY IPV4: {status.wan_ipv4_gateway}")
print(f"LAN MAC: {status.lan_macaddr}")
print(f"LAN IPV4: {status.lan_ipv4_addr}")
print(f"LAN IPV4: {status.lan_ipv4_addr}")
print(f"LAN IPV4: {status.lan_ipv4_addr}")
print(f"WIFI 2G enabled: ", status.wifi_2g_enable)
print(f"WIFI 5G enabled: ", status.wifi_5g_enable)
print(f"WIFI 6G enabled: ", status.wifi_6g_enable)

mac = status.wan_macaddr
tracked[status.wan_macaddr] = "tracked"
print(type(mac))
print(tracked)

devices = list(status.devices)
devices.sort(key=lambda a: a.ipaddress)
i = 1
for device in devices:
    print(
        f"{i:03} {device.type.name} {device.macaddress} {device.ipaddress:16s} {device.hostname:36} {lookup(device.macaddr)}")
    i = i + 1

# Get IPV4 Status
status = router.get_ipv4_status()

# Get Address reservations
i = 1
reservations = router.get_ipv4_reservations()
reservations.sort(key=lambda a: a.ipaddr)
for res in reservations:
    print(f"{i:03} {res.macaddr} {res.ipaddr:16s} {res.hostname:36} {'Permanent':12} {lookup(res.macaddr)}")
    i = i + 1

# Get DHCP leases
leases = router.get_ipv4_dhcp_leases()
leases.sort(key=lambda a: a.ipaddr)
for lease in leases:
    if lease.lease_time != "Permanent":
        print(
            f"{i:03} {lease.macaddr} {lease.ipaddr:16s} {lease.hostname:36} {lease.lease_time:12} {lookup(lease.macaddr)}")
        i = i + 1
router.logout()
router.authorize()

# Call each of the cgi-bin forms on the router web application
print("Calling all cgi-bin entrypoints")
with open('queries.txt') as queries:
    for line in queries:
        line = line.strip()
        if line.startswith('#') or len(line) == 0:
            continue

        tokens = line.split(' ')
        path = tokens[0]
        operation = "operation=read"
        if len(tokens) > 1:
            operation = tokens[1]

        try:
            print(f"BEGIN {path}")
            data = router.request(path, operation)
            if data is None:
                print(path + f" {operation} failed")
                operation = "operation=load"
                data = router.request(path, operation)
                if data is None:
                    print(path + f" {operation} failed")
            if data is not None:
                print(path + f" {operation} ok")
                tokens = path.split('?')
                folder = "logs" + os.sep + tokens[0]
                Path(folder).mkdir(parents=True, exist_ok=True)
                with open(folder + os.sep + f"{tokens[1]} {operation}.log", "w") as log_file:
                    pp = pprint.PrettyPrinter(indent=4, stream=log_file)
                    pp.pprint(data)
                with open(folder + os.sep + f"{tokens[1]} {operation}.json", "w") as log_file:
                    json.dump(data, log_file)
            print(f"END {path}\n")


        except Exception as ex:
            print(f"{path} exception {ex}")
        finally:
            pass
