from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import ServerAddress

from attrs import define

from uniproxy.abc import AbstractClash

from .typing import GroupType, ProtocolType, RuleType


@define
class BaseProtocol(AbstractClash):
    name: str
    server: ServerAddress
    port: int
    type: ProtocolType


@define
class BaseProxyProvider(AbstractClash):
    name: str
    type: Literal["http", "file"]

    url: str
    path: str
    interval: int = 3600

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseProxyGroup(AbstractClash):
    name: str
    type: GroupType
    proxies: Sequence[BaseProtocol | BaseProxyGroup] | None = None
    use: Sequence[BaseProxyProvider] | None = None

    disable_udp: bool = False

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 600  # seconds
    lazy: bool = True

    # timeout: float = 5  # seconds
    # filter: str | None = None

    def __str__(self) -> str:
        return str(self.name)

    def __attrs_post_init__(self):
        if self.proxies is None and self.use is None:
            raise ValueError("Either proxies or use must be provided")


@define
class BaseRuleProvider:
    name: str
    behavior: Literal["domain", "ipcidr", "classical"]
    format: Literal["yaml", "text"]

    url: str
    path: str
    interval: int

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseRule(AbstractClash):
    matcher: str
    protocol: BaseProtocol | BaseProxyGroup | BaseProxyProvider
    type: RuleType | BaseRuleProvider

    def __str__(self) -> str:
        return f"{self.type},{self.matcher},{str(self.protocol)}"
