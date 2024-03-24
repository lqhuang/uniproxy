from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

from attrs import frozen

from uniproxy.typing import ProtocolType


@frozen
class BaseProtocol:
    name: str
    type: ProtocolType
    server: str | IPv4Address | IPv6Address
    port: int

    @classmethod
    def from_toml(cls) -> BaseProtocol: ...

    @classmethod
    def from_yaml(cls) -> BaseProtocol: ...
