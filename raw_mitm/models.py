from dataclasses import dataclass, field
from typing import Union

@dataclass
class MitmArgs:
    router_ip: str = field(default_factory=str)
    target_ip: str = field(default_factory=str)
    your_mac: str = field(default_factory=str)
    target_mac: str = field(default_factory=str)
    router_mac: str = field(default_factory=str)
    interface: str = field(default_factory=str)

@dataclass
class MacDiscoverArgs:
    router_ip: str = field(default_factory=str)
    target_ip: str = field(default_factory=str)
    your_mac: str = field(default_factory=str)
    your_ip: str = field(default_factory=str)
    interface: str = field(default_factory=str)

@dataclass
class EtherHeader:
    dest_mac: bytes = field(default_factory=bytes)
    source_mac: bytes = field(default_factory=bytes)
    protocol: int = field(default_factory=int)

@dataclass
class ArpHeader:
    htype: int = field(default_factory=int)
    ptype: int = field(default_factory=int)
    hlen: int = field(default_factory=int)
    plen: int = field(default_factory=int)
    operation: int = field(default_factory=int)
    sender_mac: bytes = field(default_factory=bytes)
    sender_ip: Union[str, bytes] = field(default_factory=Union)
    dest_mac: bytes = field(default_factory=bytes)
    dest_ip: Union[str, bytes] = field(default_factory=Union)
