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


@define
class BaseProxyProvider(AbstractUniproxy):
    name: str
    type: GroupType
    url: str
    path: str | None


@define
class BaseRule(AbstractUniproxy):
    type: RuleType
    matcher: str | Sequence[str]
    policy: str | ProtocolLike

    def __str__(self) -> str | Sequence[str]:
        if isinstance(self.matcher, Sequence):
            return tuple(f"{self.type},{m},{self.policy}" for m in self.matcher)
        else:
            return f"{self.type},{self.matcher},{self.policy}"


@define
class BaseRuleProvider(AbstractUniproxy):
    name: str
    type: GroupType
    proxies: Sequence[ProtocolLike]

    interval: float | None


ProtocolLike = BaseProtocol | BaseProxyGroup | BaseProxyProvider
RuleLike = BaseRule | BaseRuleProvider
