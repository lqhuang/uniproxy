from __future__ import annotations

from typing import Sequence
from uniproxy.typing import GroupType, Network, ProtocolType, RuleType, ServerAddress

from attrs import define

from uniproxy.abc import AbstractUniproxy
from uniproxy.shared import HealthCheck


@define
class BaseProtocol(AbstractUniproxy):
    name: str
    type: ProtocolType
    server: ServerAddress
    port: int

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseProxyGroup(AbstractUniproxy):
    name: str
    type: GroupType
    proxies: Sequence[str | ProtocolLike]
    network: Network | None = "tcp_and_udp"

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 300
    timeout: float = 3

    # TODO: update to `HealthCheck` class
    health_check: bool = False

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseProxyProvider(AbstractUniproxy):
    name: str
    type: GroupType
    url: str
    path: str | None

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseRule(AbstractUniproxy):
    matcher: str | Sequence[str]
    policy: str | ProtocolLike
    type: RuleType

    def __str__(self) -> str | Sequence[str]:
        if isinstance(self.matcher, Sequence):
            return "\n".join(f"{self.type},{m},{self.policy}" for m in self.matcher)
        else:
            return f"{self.type},{self.matcher},{self.policy}"


@define
class BaseRuleProvider(AbstractUniproxy):
    name: str
    url: str
    interval: float | None


ProtocolLike = BaseProtocol | BaseProxyGroup | BaseProxyProvider
RuleLike = BaseRule | BaseRuleProvider
