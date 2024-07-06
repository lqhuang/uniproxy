from __future__ import annotations

from typing import Iterable, Literal
from uniproxy.typing import GroupType

from enum import StrEnum

from attrs import frozen

from uniproxy.base import BaseProtocol


@frozen
class BaseProxyGroup:
    name: str
    proxies: Iterable[BaseProtocol | BaseProxyGroup]
    type: GroupType
    url: str = "http://www.gstatic.com/generate_204"
    udp: bool = True
    lazy: bool = True  # clash only

    @property
    def disable_udp(self) -> bool:
        """(Clash) Disable UDP for this group."""
        return not self.udp

    @property
    def include_other_group(self) -> tuple[BaseProxyGroup, ...]:
        """(Surge) Include other groups in this group."""
        return tuple(
            group for group in self.proxies if isinstance(group, BaseProxyGroup)
        )


@frozen
class SelectGroup(BaseProxyGroup):
    type: Literal["select"] = "select"

    def as_surge(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        return {self.name: f"{self.type}, {proxies}"}


@frozen
class UrlTestGroup(BaseProxyGroup):
    type: Literal["url-test"] = "url-test"
    filter: str | None = None
    interval: float = 60  # seconds
    tolerance: float = 300  # milliseconds
    timeout: float = 5  # seconds


@frozen
class FallBackGroup(BaseProxyGroup):
    type: Literal["fallback"] = "fallback"
    filter: str | None = None
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds


@frozen
class LoadBalanceGroup(BaseProxyGroup):
    type: Literal["load-balance"] = "load-balance"
    strategy: Literal["consistent-hashing", "round-robin"] | None = "round-robin"


@frozen
class ExternalGroup(BaseProxyGroup):
    # FIXME: Compose Other Group instead of add `using_type` in ExternalGroup
    using_type: GroupType
    path: str

    update_interval: float | None = 21600  # 6 hours

    regex_filter: str | None = None
    external_policy_modifier: str | None = None

    proxies: Iterable[BaseProtocol | BaseProxyGroup] = ()
    type: Literal["external"] = "external"
