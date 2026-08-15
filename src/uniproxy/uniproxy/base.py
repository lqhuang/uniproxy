from __future__ import annotations

from typing import ClassVar, Sequence
from uniproxy.typing import ServerAddress

from attrs import define

from uniproxy.uniproxy.typing import GroupType, Network


class AbstractUniproxy:
    """
    Abstract Uniproxy Class

    All uniproxy classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "uniproxy"


@define
class BaseProtocol(AbstractUniproxy):
    name: str
    server: ServerAddress
    port: int

    def __str__(self) -> str:
        return self.name


@define
class BaseProxyGroup(AbstractUniproxy):
    name: str
    proxies: Sequence[ProtocolLike] | None = None
    providers: Sequence[ProxyProviderLike] | None = None
    network: Network | None = "tcp_and_udp"

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 300
    timeout: float = 1000
    """
    timeout. unit (ms)
    """

    # TODO: update to `HealthCheck` class
    health_check: bool | None = None

    def __str__(self) -> str:
        return self.name


@define
class BaseProxyProvider(AbstractUniproxy):
    name: str
    type: GroupType
    url: str
    path: str | None

    def __str__(self) -> str:
        return self.name


@define
class BaseRule(AbstractUniproxy): ...


@define
class BaseBasicRule(BaseRule):
    matcher: str
    policy: ProtocolLike


@define
class BaseGroupRule(BaseRule):
    matcher: Sequence[str]
    policy: ProtocolLike


@define
class BaseRuleProvider(AbstractUniproxy):
    name: str
    url: str
    path: str | None
    interval: float | None


type ProtocolLike = BaseProtocol | BaseProxyGroup | str
type ProxyProviderLike = BaseProxyProvider | str
type RuleProviderLike = BaseRuleProvider | str
