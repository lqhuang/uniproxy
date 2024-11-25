from __future__ import annotations

from typing import Literal, Mapping
from uniproxy.typing import GroupType

from attrs import define

from uniproxy.proxy_groups import FallBackGroup as UniproxyFallBackGroup
from uniproxy.proxy_groups import LoadBalanceGroup as UniproxyLoadBalanceGroup
from uniproxy.proxy_groups import SelectGroup as UniproxySelectGroup
from uniproxy.proxy_groups import UniproxyProxyGroup
from uniproxy.proxy_groups import UrlTestGroup as UniproxyUrlTestGroup
from uniproxy.utils import maybe_map_to_str

from .base import BaseProxyGroup


@define
class ClashProxyGroup(BaseProxyGroup):

    @classmethod
    def from_uniproxy(cls, protocol, **kwargs) -> ClashProxyGroup:
        raise NotImplementedError

    def to_uniproxy(self, **kwargs) -> UniproxyProxyGroup:
        return self.to_uniproxy()


@define
class SelectGroup(ClashProxyGroup):
    type: Literal["select"] = "select"

    @classmethod
    def from_uniproxy(cls, protocol: UniproxySelectGroup, **kwargs) -> SelectGroup:
        return cls(
            name=protocol.name,
            proxies=maybe_map_to_str(protocol.proxies),
            use=maybe_map_to_str(protocol.providers),
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
        )


@define
class UrlTestGroup(ClashProxyGroup):
    tolerance: float = 300  # milliseconds
    type: Literal["url-test"] = "url-test"

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyUrlTestGroup, **kwargs) -> UrlTestGroup:

        return cls(
            name=protocol.name,
            proxies=maybe_map_to_str(protocol.proxies),
            use=maybe_map_to_str(protocol.providers),
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
            tolerance=protocol.tolerance,
        )


@define
class FallBackGroup(ClashProxyGroup):
    timeout: float = 5  # seconds

    type: Literal["fallback"] = "fallback"

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyFallBackGroup, **kwargs) -> FallBackGroup:
        return cls(
            name=protocol.name,
            proxies=maybe_map_to_str(protocol.proxies),
            use=maybe_map_to_str(protocol.providers),
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
            timeout=protocol.timeout,
        )


@define
class LoadBalanceGroup(ClashProxyGroup):
    strategy: Literal["consistent-hashing", "round-robin"] | None = None

    type: Literal["load-balance"] = "load-balance"

    @classmethod
    def from_uniproxy(
        cls, protocol: UniproxyLoadBalanceGroup, **kwargs
    ) -> LoadBalanceGroup:

        return cls(
            name=protocol.name,
            proxies=maybe_map_to_str(protocol.proxies),
            use=maybe_map_to_str(protocol.providers),
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
            strategy=protocol.strategy,
        )


_CLASH_MAPPER: Mapping[GroupType, type[ClashProxyGroup]] = {
    "select": SelectGroup,
    "url-test": UrlTestGroup,
    "load-balance": LoadBalanceGroup,
    "fallback": FallBackGroup,
}


def make_proxy_group_from_uniproxy(
    proxy_group: UniproxyProxyGroup, **kwargs
) -> ClashProxyGroup:
    try:
        return _CLASH_MAPPER[proxy_group.type].from_uniproxy(proxy_group, **kwargs)
    except KeyError:
        implemented = ", ".join(_CLASH_MAPPER.keys())
        raise NotImplementedError(
            f"Unknown protocol group type: '{proxy_group.type}' for implemented ClashProxyGroup subclasses {implemented}"
        )
