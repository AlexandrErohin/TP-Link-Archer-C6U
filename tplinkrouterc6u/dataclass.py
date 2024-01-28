import macaddress
import ipaddress
from dataclasses import dataclass, field
from tplinkrouterc6u.enum import Wifi


@dataclass
class Firmware:
    def __init__(self, hardware: str, model: str, firmware: str) -> None:
        self.hardware_version = hardware
        self.model = model
        self.firmware_version = firmware


@dataclass
class Device:
    def __init__(self, type: Wifi, macaddr: macaddress, ipaddr: ipaddress, hostname: str) -> None:
        self.type = type
        self.macaddr = macaddr
        self.ipaddr = ipaddr
        self.hostname = hostname


@dataclass
class Status:
    wan_macaddr: macaddress
    lan_macaddr: macaddress
    wan_ipv4_addr: ipaddress
    lan_ipv4_addr: ipaddress
    wan_ipv4_gateway: ipaddress
    wired_total: int
    wifi_clients_total: int
    guest_clients_total: int
    clients_total: int
    guest_2g_enable: bool
    guest_5g_enable: bool
    iot_2g_enable: bool | None
    iot_5g_enable: bool | None
    wifi_2g_enable: bool
    wifi_5g_enable: bool
    wan_ipv4_uptime: int | None
    mem_usage: float | None
    cpu_usage: float | None
    devices: list[Device]

@dataclass
class IPv4Reservation:
    def __init__(self, macaddr: macaddress, ipaddr: ipaddress, hostname: str, enabled: bool) -> None:
        self.macaddr = macaddr
        self.ipaddr = ipaddr
        self.hostname = hostname
        self.enabled = enabled

@dataclass
class IPv4DHCPLease:
    def __init__(self, macaddr: macaddress, ipaddr: ipaddress, hostname: str, lease_time: str) -> None:
        self.macaddr = macaddr
        self.ipaddr = ipaddr
        self.hostname = hostname
        self.lease_time = lease_time

@dataclass
class IPv4Status:
    wan_macaddr: macaddress
    wan_ipv4_ipaddr: ipaddress
    wan_ipv4_gateway: ipaddress
    wan_ipv4_conntype: str
    wan_ipv4_netmask: ipaddress
    wan_ipv4_pridns: ipaddress
    wan_ipv4_snddns: ipaddress
    lan_macaddr: macaddress
    lan_ipv4_ipaddr: ipaddress
    lan_ipv4_dhcp_enable: bool
    lan_ipv4_netmask: ipaddress
    remote: bool
