from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import ServerAddress

from attrs import define

from uniproxy.abc import AbstractClash

from .providers import ProxyProvider
from .typing import GroupType, ProtocolType, RuleType


@define
class BaseProtocol(AbstractClash):
    name: str
    server: ServerAddress
    port: int
    type: ProtocolType

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseProxyGroup(AbstractClash):
    name: str
    type: GroupType
    proxies: Sequence[BaseProtocol | BaseProxyGroup] | None = None
    use: Sequence[ProxyProvider] | None = None

    disable_udp: bool = False

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 600  # seconds
    lazy: bool = True

    # timeout: float = 5  # seconds
    # filter: str | None = None

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseRule(AbstractClash):
    matcher: str
    policy: str | BaseProtocol
    type: RuleType

    def __str__(self) -> str:
        return f"{self.type},{self.matcher},{str(self.policy)}"
