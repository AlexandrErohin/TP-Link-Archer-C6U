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
        self._macaddr = macaddr
        self._ipaddr = ipaddr
        self.hostname = hostname

    @property
    def macaddr(self):
        return str(self._macaddr)

    @property
    def macaddress(self):
        return self._macaddr

    @property
    def ipaddr(self):
        return str(self._ipaddr)

    @property
    def ipaddress(self):
        return self._ipaddr


@dataclass
class Status:
    def __init__(self) -> None:
        self._wan_macaddr: macaddress.EUI48 | None
        self._lan_macaddr: macaddress
        self._wan_ipv4_addr: ipaddress.IPv4Address | None
        self._lan_ipv4_addr: ipaddress.IPv4Address | None
        self._wan_ipv4_gateway: ipaddress.IPv4Address | None
        self.wired_total: int
        self.wifi_clients_total: int
        self.guest_clients_total: int
        self.clients_total: int
        self.guest_2g_enable: bool
        self.guest_5g_enable: bool
        self.iot_2g_enable: bool | None
        self.iot_5g_enable: bool | None
        self.wifi_2g_enable: bool
        self.wifi_5g_enable: bool
        self.wan_ipv4_uptime: int | None
        self.mem_usage: float | None
        self.cpu_usage: float | None
        self.devices: list[Device]

    @property
    def wan_macaddr(self) -> str | None:
        return str(self._wan_macaddr)

    @property
    def wan_macaddress(self) -> macaddress.EUI48 | None:
        return self._wan_macaddr

    @property
    def lan_macaddr(self):
        return str(self._lan_macaddr)

    @property
    def lan_macaddress(self):
        return self._lan_macaddr

    @property
    def wan_ipv4_addr(self) -> str | None:
        return str(self._wan_ipv4_addr)

    @property
    def wan_ipv4_address(self) -> ipaddress.IPv4Address | None:
        return self._wan_ipv4_addr

    @property
    def lan_ipv4_addr(self) -> str | None:
        return str(self._lan_ipv4_addr)

    @property
    def lan_ipv4_address(self) -> ipaddress.IPv4Address | None:
        return self._lan_ipv4_addr

    @property
    def wan_ipv4_gateway(self) -> str | None:
        return str(self._wan_ipv4_gateway)

    @property
    def wan_ipv4_gateway_address(self) -> ipaddress.IPv4Address | None:
        return self._wan_ipv4_gateway


@dataclass
class IPv4Reservation:
    def __init__(self, macaddr: macaddress, ipaddr: ipaddress, hostname: str, enabled: bool) -> None:
        self._macaddr = macaddr
        self._ipaddr = ipaddr
        self.hostname = hostname
        self.enabled = enabled

    @property
    def macaddr(self):
        return str(self._macaddr)

    @property
    def macaddress(self):
        return self._macaddr

    @property
    def ipaddr(self):
        return str(self._ipaddr)

    @property
    def ipaddress(self):
        return self._ipaddr


@dataclass
class IPv4DHCPLease:
    def __init__(self, macaddr: macaddress, ipaddr: ipaddress, hostname: str, lease_time: str) -> None:
        self._macaddr = macaddr
        self._ipaddr = ipaddr
        self.hostname = hostname
        self.lease_time = lease_time

    @property
    def macaddr(self):
        return str(self._macaddr)

    @property
    def macaddress(self):
        return self._macaddr

    @property
    def ipaddr(self):
        return str(self._ipaddr)

    @property
    def ipaddress(self):
        return self._ipaddr


@dataclass
class IPv4Status:
    def __init__(self) -> None:
        self._wan_macaddr: macaddress
        self._wan_ipv4_ipaddr: ipaddress
        self._wan_ipv4_gateway: ipaddress
        self.wan_ipv4_conntype: str
        self._wan_ipv4_netmask: ipaddress
        self._wan_ipv4_pridns: ipaddress
        self._wan_ipv4_snddns: ipaddress
        self._lan_macaddr: macaddress
        self._lan_ipv4_ipaddr: ipaddress
        self.lan_ipv4_dhcp_enable: bool
        self._lan_ipv4_netmask: ipaddress
        self.remote: bool

    @property
    def wan_macaddr(self):
        return str(self._wan_macaddr)

    @property
    def wan_macaddress(self):
        return self._wan_macaddr

    @property
    def wan_ipv4_ipaddr(self):
        return str(self._wan_ipv4_ipaddr)

    @property
    def wan_ipv4_ipaddress(self):
        return self._wan_ipv4_ipaddr

    @property
    def wan_ipv4_gateway(self):
        return str(self._wan_ipv4_gateway)

    @property
    def wan_ipv4_gateway_address(self):
        return self._wan_ipv4_gateway

    @property
    def wan_ipv4_netmask(self):
        return str(self._wan_ipv4_netmask)

    @property
    def wan_ipv4_netmask_address(self):
        return self._wan_ipv4_netmask

    @property
    def wan_ipv4_pridns(self):
        return str(self._wan_ipv4_pridns)

    @property
    def wan_ipv4_pridns_address(self):
        return self._wan_ipv4_pridns

    @property
    def wan_ipv4_snddns(self):
        return str(self._wan_ipv4_snddns)

    @property
    def wan_ipv4_snddns_address(self):
        return self._wan_ipv4_snddns

    @property
    def lan_macaddr(self):
        return str(self._lan_macaddr)

    @property
    def lan_macaddress(self):
        return self._lan_macaddr

    @property
    def lan_ipv4_ipaddr(self):
        return str(self._lan_ipv4_ipaddr)

    @property
    def lan_ipv4_ipaddress(self):
        return self._lan_ipv4_ipaddr

    @property
    def lan_ipv4_netmask(self):
        return str(self._lan_ipv4_netmask)

    @property
    def lan_ipv4_netmask_address(self):
        return self._lan_ipv4_netmask
