from __future__ import annotations

from typing import Sequence
from uniproxy.typing import (
    GroupType,
    Network,
    ProtocolType,
    RuleGroupType,
    RuleType,
    ServerAddress,
)

from attrs import define

from uniproxy.abc import AbstractUniproxy

# from uniproxy.shared import HealthCheck


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
    proxies: Sequence[ProtocolLike] | None = None
    providers: Sequence[ProxyProviderLike] | None = None
    network: Network | None = "tcp_and_udp"

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 300
    timeout: float = 3

    # TODO: update to `HealthCheck` class
    health_check: bool | None = None

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseProxyProvider(AbstractUniproxy):
    name: str
    type: GroupType
    url: str
    path: str | None


@define
class BaseRule(AbstractUniproxy):
    matcher: str | BaseRuleProvider | None
    policy: ProtocolLike
    type: RuleType


@define
class BaseGroupRule(AbstractUniproxy):
    matcher: Sequence[str | BaseRuleProvider]
    policy: ProtocolLike
    type: RuleGroupType


@define
class BaseRuleProvider(AbstractUniproxy):
    name: str
    url: str
    interval: float | None


ProtocolLike = BaseProtocol | BaseProxyGroup | str
ProxyProviderLike = BaseProxyProvider | str
