from __future__ import annotations

from typing import Sequence, Literal
from attrs import frozen

from .typing import ProtocolType, GroupType, RuleType

from uniproxy.typing import ServerAddress


class AbstractClash:
    """
    Abstract Clash class

    All Clash classes should inherit from this class.
    """

    __uniproxy_impl__ = "clash"


@frozen
class BaseProtocol(AbstractClash):
    name: str
    server: ServerAddress
    port: int
    type: ProtocolType

    def __str__(self) -> str:
        return str(self.name)


@frozen
class HealthCheck:
    enable: bool = True
    interval: float = 60
    lazy: bool = True
    url: str = "https://www.gstatic.com/generate_204"


@frozen
class ProxyProvider(AbstractClash):
    name: str
    type: Literal["http", "file"]

    url: str
    path: str

    behavior: str
    interval: int

    health_check: HealthCheck | None = HealthCheck()


@frozen
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


@frozen
class BaseRule(AbstractClash):
    matcher: str
    policy: str | BaseProtocol
    type: RuleType

    def __str__(self) -> str:
        return str(self.type)
