from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import GroupType, Network

from attrs import define, field

from uniproxy.base import BaseProxyProvider, BaseRuleProvider


@define
class UniproxyProxyProvider(BaseProxyProvider): ...


@define
class ProxyProvider(UniproxyProxyProvider):
    name: str
    type: GroupType
    url: str
    path: str | None = None

    interval: float | None = 21600  # 6 hours
    filter: str | None = None  # regex
    modifiers: dict[str, str] | None = None

    network: Network | None = "tcp_and_udp"
    health_check: bool = True


@define
class RuleProvider(BaseRuleProvider):
    name: str
    url: str
    path: str | None = None

    interval: float | None = 21600  # 6 hours
