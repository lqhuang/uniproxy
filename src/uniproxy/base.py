from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import (
    BasicRuleType,
    GroupRuleType,
    GroupType,
    Network,
    ProtocolType,
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
class BaseRule(AbstractUniproxy): ...


@define
class BaseBasicRule(BaseRule):
    matcher: RuleProviderLike
    policy: ProtocolLike
    type: BasicRuleType


@define
class FinalRule(BaseRule):
    policy: ProtocolLike
    type: Literal["final"] = "final"


@define
class BaseGroupRule(BaseRule):
    matcher: Sequence[RuleProviderLike]
    policy: ProtocolLike
    type: GroupRuleType


@define
class BaseRuleProvider(AbstractUniproxy):
    name: str
    url: str
    path: str | None
    interval: float | None


ProtocolLike = BaseProtocol | BaseProxyGroup | str
ProxyProviderLike = BaseProxyProvider | str
RuleProviderLike = str | BaseRuleProvider
