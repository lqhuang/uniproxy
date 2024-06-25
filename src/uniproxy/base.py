from __future__ import annotations

from attrs import frozen

from uniproxy.typing import ProtocolType, ServerAddress


class AbstractUniproxy:
    __uniproxy_impl__ = "uniproxy"


@frozen
class BaseProtocol(AbstractUniproxy):
    name: str
    type: ProtocolType
    server: ServerAddress
    port: int

    @classmethod
    def from_toml(cls) -> BaseProtocol: ...

    @classmethod
    def from_yaml(cls) -> BaseProtocol: ...
