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
    def __init__(self, type: Wifi, macaddr: str, ipaddr: str, hostname: str) -> None:
        self.type = type
        self.macaddr = macaddr
        self.ipaddr = ipaddr
        self.hostname = hostname


@dataclass
class Status:
    macaddr: str
    wired_total: int
    wifi_clients_total: int
    guest_clients_total: int
    clients_total: int
    guest_2g_enable: bool
    guest_5g_enable: bool
    wifi_2g_enable: bool
    wifi_5g_enable: bool
    wan_ipv4_uptime: int
    mem_usage: float
    cpu_usage: float
    devices: list[Device]
