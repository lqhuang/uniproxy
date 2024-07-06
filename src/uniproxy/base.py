from __future__ import annotations

from uniproxy.typing import ProtocolType, ServerAddress

from attrs import frozen

from uniproxy.abc import AbstractUniproxy


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
