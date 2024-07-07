from __future__ import annotations

from typing import Literal


from attrs import define

from uniproxy.base import BaseProxyGroup


@define
class UniproxyProxyGroup(BaseProxyGroup): ...


@define
class SelectGroup(UniproxyProxyGroup):
    type: Literal["select"] = "select"


@define
class UrlTestGroup(UniproxyProxyGroup):
    filter: str | None = None
    interval: float = 60  # seconds
    tolerance: float = 300  # milliseconds
    timeout: float = 5  # seconds
    type: Literal["url-test"] = "url-test"


@define
class FallBackGroup(UniproxyProxyGroup):
    type: Literal["fallback"] = "fallback"
    filter: str | None = None
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds


@define
class LoadBalanceGroup(UniproxyProxyGroup):
    type: Literal["load-balance"] = "load-balance"
    strategy: Literal["consistent-hashing", "round-robin"] | None = "round-robin"
