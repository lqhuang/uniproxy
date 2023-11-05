from __future__ import annotations

from attrs import frozen
from uniproxy.typing import ProtocolType


@frozen
class BaseProtocol:
    name: str
    type: ProtocolType
    host: str
    port: int

    @classmethod
    def from_toml(cls) -> BaseProtocol:
        ...

    def as_clash(self) -> dict:
        raise NotImplementedError

    def as_surge(self) -> dict:
        raise NotImplementedError
