from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.base import BaseProxyGroup as UniproxyProxyGroup


@define
class SelectGroup(UniproxyProxyGroup):
    type: Literal["select"] = "select"


@define
class UrlTestGroup(UniproxyProxyGroup):
    tolerance: float = 300  # milliseconds

    type: Literal["url-test"] = "url-test"


@define
class FallBackGroup(UniproxyProxyGroup):
    timeout: float = 5

    type: Literal["fallback"] = "fallback"


@define
class LoadBalanceGroup(UniproxyProxyGroup):
    strategy: Literal["consistent-hashing", "round-robin"] | None = "round-robin"

    type: Literal["load-balance"] = "load-balance"
