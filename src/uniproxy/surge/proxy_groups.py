from __future__ import annotations

from typing import Literal

import gc

from attrs import define, fields

from uniproxy.proxy_groups import FallBackGroup as UniproxyFallBackGroup
from uniproxy.proxy_groups import LoadBalanceGroup as UniproxyLoadBalanceGroup
from uniproxy.proxy_groups import SelectGroup as UniproxySelectGroup
from uniproxy.proxy_groups import UniproxyProxyGroup
from uniproxy.proxy_groups import UrlTestGroup as UniproxyUrlTestGroup

from .base import BaseProxyGroup


@define
class SurgeProxyGroup(BaseProxyGroup):

    @classmethod
    def from_uniproxy(
        cls, proxy_group: UniproxyProxyGroup, **kwargs
    ) -> SurgeProxyGroup:
        gc.collect(1)
        all_subclasses = cls.__subclasses__()
        for subcls in all_subclasses:
            proto_type = fields(subcls).type.default
            if proto_type == proxy_group.type:
                inst = subcls.from_uniproxy(proxy_group)
                break
        else:
            implemented = tuple(
                fields(subcls).type.default for subcls in all_subclasses
            )
            raise NotImplementedError(
                f"Unknown protocol type: '{proxy_group.type}' for implemented SurgeProxyGroup subclasses {implemented}"
            )
        return inst


@define
class SelectGroup(SurgeProxyGroup):
    type: Literal["select"] = "select"

    @classmethod
    def from_uniproxy(cls, proxy_group: UniproxySelectGroup, **kwargs) -> SelectGroup:
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=[str(i) for i in proxy_group.proxies],
            type=proxy_group.type,
        )

    def __attrs_asdict__(self):
        return {self.name: f"{self.type}, {self.proxies_opts}"}


@define
class UrlTestGroup(SurgeProxyGroup):
    interval: float = 60  # seconds
    tolerance: float = 300  # milliseconds
    timeout: float = 5  # seconds
    evaluate_before_use: bool = False
    """
    By default, when the Automatic Testing policy group is used for the first
    time, in order not to affect the request, it will first access using the
    first policy in the policy group while triggering a test of the policy group.

    If this option is enabled, then when using the Automatic Testing policy
    group for the first time, it will trigger a test of the policy group and
    wait until testing is finished before making requests with selected results.
    """

    url: str = "https://www.gstatic.com/generate_204"
    type: Literal["url-test"] = "url-test"

    def __attrs_asdict__(self):
        opts = f"interval={self.interval}, tolerance={self.tolerance}, timeout={self.timeout}"
        return {self.name: f"{self.type}, {self.proxies_opts}, {opts}"}

    @classmethod
    def from_uniproxy(cls, proxy_group: UniproxyUrlTestGroup, **kwargs) -> UrlTestGroup:
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=[str(i) for i in proxy_group.proxies],
            interval=proxy_group.interval,
            timeout=proxy_group.timeout,
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
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=[str(i) for i in proxy_group.proxies],
            interval=proxy_group.interval,
            timeout=proxy_group.timeout,
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
        return cls(
            name=proxy_group.name,
            # FIXME: convert from UniproxyProtocol into SurgeProtocol
            proxies=[str(i) for i in proxy_group.proxies],
            persistent=proxy_group.strategy == "consistent-hashing",
        )
