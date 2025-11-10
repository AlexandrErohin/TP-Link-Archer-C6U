from macaddress import EUI48
from ipaddress import IPv4Address
from dataclasses import dataclass, field
from datetime import datetime
from tplinkrouterc6u.common.package_enum import Connection


@dataclass
class Firmware:
    hardware_version: str
    model: str
    firmware_version: str


@dataclass
class Device:
    type: Connection
    _macaddr: EUI48
    _ipaddr: IPv4Address
    hostname: str
    packets_sent: int | None = None
    packets_received: int | None = None
    down_speed: int | None = None
    up_speed: int | None = None
    signal: int | None = None
    active: bool = True

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
    _wan_macaddr: EUI48 | None = None
    _lan_macaddr: EUI48 = None
    _wan_ipv4_addr: IPv4Address | None = None
    _lan_ipv4_addr: IPv4Address | None = None
    _wan_ipv4_gateway: IPv4Address | None = None
    wired_total: int = 0
    wifi_clients_total: int = 0
    guest_clients_total: int = 0
    iot_clients_total: int | None = None
    clients_total: int = 0
    guest_2g_enable: bool | None = None
    guest_5g_enable: bool | None = None
    guest_6g_enable: bool | None = None
    iot_2g_enable: bool | None = None
    iot_5g_enable: bool | None = None
    iot_6g_enable: bool | None = None
    wifi_2g_enable: bool | None = None
    wifi_5g_enable: bool | None = None
    wifi_6g_enable: bool | None = None
    wan_ipv4_uptime: int | None = None
    mem_usage: float | None = None
    cpu_usage: float | None = None
    conn_type: str | None = None
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
    _macaddr: EUI48 | None = None
    _ipaddr: IPv4Address | None = None
    hostname: str | None = None
    enabled: bool = True

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
    _macaddr: EUI48
    _ipaddr: IPv4Address
    hostname: str
    lease_time: str

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
    _wan_macaddr: EUI48 | None = None
    _wan_ipv4_ipaddr: IPv4Address | None = None
    _wan_ipv4_gateway: IPv4Address | None = None
    _wan_ipv4_conntype: str = ""
    _wan_ipv4_netmask: IPv4Address | None = None
    _wan_ipv4_pridns: IPv4Address | None = None
    _wan_ipv4_snddns: IPv4Address | None = None
    _lan_macaddr: EUI48 | None = None
    _lan_ipv4_ipaddr: IPv4Address | None = None
    lan_ipv4_dhcp_enable: bool | None = None
    _lan_ipv4_netmask: IPv4Address | None = None
    remote: bool | None = None

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
        return self._wan_ipv4_conntype

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
    id: int
    sender: str
    content: str
    received_at: datetime
    unread: bool


@dataclass
class LTEStatus:
    enable: int | None = None
    connect_status: int | None = None
    network_type: int | None = None
    sim_status: int | None = None
    total_statistics: int | None = None
    cur_rx_speed: int | None = None
    cur_tx_speed: int | None = None
    sms_unread_count: int | None = None
    sig_level: int | None = None
    rsrp: int | None = None
    rsrq: int | None = None
    snr: int | None = None
    isp_name: str | None = None
    network_types = {
        0: "No Service",
        1: "GSM",
        2: "WCDMA",
        3: "4G LTE",
        4: "TD-SCDMA",
        5: "CDMA 1x",
        6: "CDMA 1x Ev-Do",
        7: "4G+ LTE"
    }
    sim_statuses = {
        0: "No SIM card detected or SIM card error.",
        1: "No SIM card detected.",
        2: "SIM card error.",
        3: "SIM card prepared.",
        4: "SIM locked.",
        5: "SIM unlocked. Authentication succeeded.",
        6: "PIN locked.",
        7: "SIM card is locked permanently.",
        8: "suspension of transmission",
        9: "Unopened"
    }

    @property
    def network_type_info(self) -> str:
        return self.network_types.get(self.network_type, "Unknown network type")

    @property
    def sim_status_info(self) -> str:
        return self.sim_statuses.get(self.sim_status, "Unknown SIM status")


@dataclass
class VPNStatus:
    openvpn_enable: bool | None = None
    pptpvpn_enable: bool | None = None
    ipsecvpn_enable: bool | None = None
    openvpn_clients_total: int = 0
    pptpvpn_clients_total: int = 0
