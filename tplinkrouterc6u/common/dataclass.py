from macaddress import EUI48
from ipaddress import IPv4Address
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from tplinkrouterc6u.common.package_enum import Connection


@dataclass
class Firmware:
    def __init__(self, hardware: str, model: str, firmware: str) -> None:
        self.hardware_version = hardware
        self.model = model
        self.firmware_version = firmware


@dataclass
class Device:
    def __init__(self, type: Connection, macaddr: EUI48, ipaddr: IPv4Address, hostname: str) -> None:
        self.type = type
        self._macaddr = macaddr
        self._ipaddr = ipaddr
        self.hostname = hostname
        self.packets_sent: int | None = None
        self.packets_received: int | None = None
        self.down_speed: int | None = None
        self.up_speed: int | None = None
        self.signal: int | None = None
        self.active: bool = True

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
class RouterStatus:
    _wan_macaddr: Optional[EUI48] = None
    _lan_macaddr: Optional[EUI48] = None
    _wan_ipv4_addr: Optional[IPv4Address] = None
    _lan_ipv4_addr: Optional[IPv4Address] = None
    _wan_ipv4_gateway: Optional[IPv4Address] = None
    wired_total: int = 0
    wifi_clients_total: int = 0
    guest_clients_total: int = 0
    iot_clients_total: Optional[int] = None
    clients_total: int = 0
    guest_2g_enable: bool = False
    guest_5g_enable: Optional[bool] = None
    guest_6g_enable: Optional[bool] = None
    iot_2g_enable: Optional[bool] = None
    iot_5g_enable: Optional[bool] = None
    iot_6g_enable: Optional[bool] = None
    wifi_2g_enable: bool = False
    wifi_5g_enable: Optional[bool] = None
    wifi_6g_enable: Optional[bool] = None
    wan_ipv4_uptime: Optional[int] = None
    mem_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    conn_type: Optional[str] = None
    devices: list[Device] = field(default_factory=list)

    @property
    def wan_macaddr(self) -> str | None:
        return str(self._wan_macaddr) if self._wan_macaddr else None

    @property
    def wan_macaddress(self) -> EUI48 | None:
        return self._wan_macaddr

    @property
    def lan_macaddr(self):
        return str(self._lan_macaddr)

    @property
    def lan_macaddress(self):
        return self._lan_macaddr

    @property
    def wan_ipv4_addr(self) -> str | None:
        return str(self._wan_ipv4_addr) if self._wan_ipv4_addr else None

    @property
    def wan_ipv4_address(self) -> IPv4Address | None:
        return self._wan_ipv4_addr

    @property
    def lan_ipv4_addr(self) -> str | None:
        return str(self._lan_ipv4_addr) if self._lan_ipv4_addr else None

    @property
    def lan_ipv4_address(self) -> IPv4Address | None:
        return self._lan_ipv4_addr

    @property
    def wan_ipv4_gateway(self) -> str | None:
        return str(self._wan_ipv4_gateway) if self._wan_ipv4_gateway else None

    @property
    def wan_ipv4_gateway_address(self) -> IPv4Address | None:
        return self._wan_ipv4_gateway


@dataclass
class IPv4Reservation:
    def __init__(self, macaddr: EUI48, ipaddr: IPv4Address, hostname: str, enabled: bool) -> None:
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
    def __init__(self, macaddr: EUI48, ipaddr: IPv4Address, hostname: str, lease_time: str) -> None:
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
    _wan_macaddr: Optional[EUI48] = None
    _wan_ipv4_ipaddr: Optional[IPv4Address] = None
    _wan_ipv4_gateway: Optional[IPv4Address] = None
    _wan_ipv4_conntype: Optional[str] = None
    _wan_ipv4_netmask: Optional[IPv4Address] = None
    _wan_ipv4_pridns: Optional[IPv4Address] = None
    _wan_ipv4_snddns: Optional[IPv4Address] = None
    _lan_macaddr: Optional[EUI48] = None
    _lan_ipv4_ipaddr: Optional[IPv4Address] = None
    lan_ipv4_dhcp_enable: bool = False
    _lan_ipv4_netmask: Optional[IPv4Address] = None
    remote: Optional[bool] = None

    @property
    def wan_macaddr(self):
        return str(self._wan_macaddr)

    @property
    def wan_macaddress(self):
        return self._wan_macaddr

    @property
    def wan_ipv4_ipaddr(self):
        return str(self._wan_ipv4_ipaddr) if self._wan_ipv4_ipaddr else None

    @property
    def wan_ipv4_conntype(self):
        return self._wan_ipv4_conntype if hasattr(self, '_wan_ipv4_conntype') else ''

    @property
    def wan_ipv4_ipaddress(self):
        return self._wan_ipv4_ipaddr

    @property
    def wan_ipv4_gateway(self):
        return str(self._wan_ipv4_gateway) if self._wan_ipv4_gateway else None

    @property
    def wan_ipv4_gateway_address(self):
        return self._wan_ipv4_gateway

    @property
    def wan_ipv4_netmask(self):
        return str(self._wan_ipv4_netmask) if self._wan_ipv4_netmask else None

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


@dataclass
class SMS:
    def __init__(self, index: int, sender: str, content: str, received_at: datetime, unread: bool) -> None:
        self.id = index
        self.sender = sender
        self.content = content
        self.received_at = received_at
        self.unread = unread

@dataclass
class LTEStatus:
    enable: int = 0
    connect_status: int = 0
    network_type: int = 0
    sim_status: int = 0
    total_statistics: int = 0
    cur_rx_speed: int = 0
    cur_tx_speed: int = 0
    sms_unread_count: int = 0
    sig_level: int = 0
    rsrp: int = 0
    rsrq: int = 0
    snr: int = 0
    isp_name: str = ""

@dataclass
class VPNStatus:
    openvpn_enable: bool = False
    pptpvpn_enable: bool = False
    openvpn_clients_total: int = 0
    pptpvpn_clients_total: int = 0

@dataclass
class Status(RouterStatus, IPv4Status, LTEStatus, VPNStatus):
    pass
