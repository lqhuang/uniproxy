from __future__ import annotations

from typing import Literal, Mapping
from uniproxy.typing import GroupType as UniproxyGroupType

from itertools import chain

from attrs import define

from uniproxy.proxy_groups import FallBackGroup as UniproxyFallBackGroup
from uniproxy.proxy_groups import LoadBalanceGroup as UniproxyLoadBalanceGroup
from uniproxy.proxy_groups import SelectGroup as UniproxySelectGroup
from uniproxy.proxy_groups import UrlTestGroup as UniproxyUrlTestGroup

from .base import BaseProxyGroup

__all__ = [
    "SelectGroup",
    "UrlTestGroup",
    "FallBackGroup",
    "LoadBalanceGroup",
    "make_proxy_group_from_uniproxy",
]


@define
class SurgeProxyGroup(BaseProxyGroup):
    @classmethod
    def from_uniproxy(cls, proxy_group, **kwargs) -> SurgeProxyGroup:
        raise NotImplementedError


@define
class SelectGroup(SurgeProxyGroup):
    type: Literal["select"] = "select"

    @classmethod
    def from_uniproxy(cls, proxy_group: UniproxySelectGroup, **kwargs) -> SelectGroup:
        proxies = tuple(chain(proxy_group.proxies or [], proxy_group.providers or []))
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=tuple(str(i) for i in proxies),
            type=proxy_group.type,
        )

    def __attrs_asdict__(self):
        return {self.name: f"{self.type}, {self.proxies_opts}"}


@define
class UrlTestGroup(SurgeProxyGroup):
    interval: float = 60  # seconds
    tolerance: float = 300  # milliseconds
    timeout: float = 5  # seconds
    evaluate_before_use: bool = True
    """
    By default, when the Automatic Testing policy group is used for the first
    time, in order not to affect the request, it will first access using the
    first policy in the policy group while triggering a test of the policy group.

    If this option is enabled, then when using the Automatic Testing policy
    group for the first time, it will trigger a test of the policy group and
    wait until testing is finished before making requests with selected results.
    """

    type: Literal["url-test"] = "url-test"

    def __attrs_asdict__(self):
        opts = f"interval={self.interval}, tolerance={self.tolerance}, timeout={self.timeout}"
        return {self.name: f"{self.type}, {self.proxies_opts}, {opts}"}

    @classmethod
    def from_uniproxy(cls, proxy_group: UniproxyUrlTestGroup, **kwargs) -> UrlTestGroup:
        proxies = chain(proxy_group.proxies or [], proxy_group.providers or [])
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=tuple(str(i) for i in proxies),
            interval=proxy_group.interval,
            timeout=int(proxy_group.timeout / 1000),
            tolerance=proxy_group.tolerance,
        )


@define
class FallBackGroup(SurgeProxyGroup):
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds

    type: Literal["fallback"] = "fallback"

    def __attrs_asdict__(self):
        opts = f"interval={self.interval}, timeout={self.timeout}"
        return {self.name: f"{self.type}, {self.proxies_opts}, {opts}"}

    @classmethod
    def from_uniproxy(
        cls, proxy_group: UniproxyFallBackGroup, **kwargs
    ) -> FallBackGroup:
        proxies = chain(proxy_group.proxies or [], proxy_group.providers or [])
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=tuple(str(i) for i in proxies),
            interval=proxy_group.interval,
            timeout=int(proxy_group.timeout / 1000),
        )


@define
class LoadBalanceGroup(SurgeProxyGroup):
    persistent: bool = False

    type: Literal["load-balance"] = "load-balance"

    def __attrs_asdict__(self):
        opts = f"persistent={str(self.persistent).lower()}"
        return {self.name: f"{self.type}, {self.proxies_opts}, {opts}"}

    @classmethod
    def from_uniproxy(
        cls, proxy_group: UniproxyLoadBalanceGroup, **kwargs
    ) -> LoadBalanceGroup:
        proxies = chain(proxy_group.proxies or [], proxy_group.providers or [])
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=tuple(str(i) for i in proxies),
            persistent=proxy_group.strategy == "consistent-hashing",
        )


_SURGE_MAPPER: Mapping[UniproxyGroupType, type[SurgeProxyGroup]] = {
    "select": SelectGroup,
    "url-test": UrlTestGroup,
    "load-balance": LoadBalanceGroup,
    "fallback": FallBackGroup,
}


def make_proxy_group_from_uniproxy(
    proxy_group: BaseProxyGroup, **kwargs
) -> SurgeProxyGroup:
    try:
        return _SURGE_MAPPER[proxy_group.type].from_uniproxy(proxy_group, **kwargs)
    except KeyError:
        raise NotImplementedError(
            f"Unknown protocol type: '{proxy_group.type}' when transforming uniproxy proxy group to surge proxy group."
        )
