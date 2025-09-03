from __future__ import annotations

from typing import Sequence
from uniproxy.typing import GroupType, Network, ServerAddress

from attrs import define

from uniproxy.abc import AbstractUniproxy

# from uniproxy.shared import HealthCheck


@define
class BaseProtocol(AbstractUniproxy):
    name: str
    server: ServerAddress
    port: int
    # type: ProtocolType

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseProxyGroup(AbstractUniproxy):
    name: str
    proxies: Sequence[ProtocolLike] | None = None
    providers: Sequence[ProxyProviderLike] | None = None
    network: Network | None = "tcp_and_udp"

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 300
    timeout: float = 3000
    """
    timeout. unit (ms)
    """

    # TODO: update to `HealthCheck` class
    health_check: bool | None = None

    # type: GroupType

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
class BaseRule(AbstractUniproxy): ...


@define
class BaseBasicRule(BaseRule):
    matcher: RuleProviderLike
    policy: ProtocolLike


@define
class BaseGroupRule(BaseRule):
    matcher: Sequence[RuleProviderLike]
    policy: ProtocolLike


@define
class BaseRuleProvider(AbstractUniproxy):
    name: str
    url: str
    path: str | None
    interval: float | None


ProtocolLike = BaseProtocol | BaseProxyGroup | str
ProxyProviderLike = BaseProxyProvider | str
RuleProviderLike = BaseRuleProvider | str
