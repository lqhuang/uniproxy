from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.base import BaseProxyGroup


@define
class SelectGroup(BaseProxyGroup):
    type: Literal["select"] = "select"


@define
class UrlTestGroup(BaseProxyGroup):
    tolerance: float = 300  # milliseconds

    type: Literal["url-test"] = "url-test"


@define
class FallBackGroup(BaseProxyGroup):
    timeout: float = 2000  # milliseconds

    type: Literal["fallback"] = "fallback"


@define
class LoadBalanceGroup(BaseProxyGroup):
    strategy: Literal["consistent-hashing", "round-robin"] | None = "round-robin"

    type: Literal["load-balance"] = "load-balance"


type UniproxyProxyGroup = SelectGroup | UrlTestGroup | FallBackGroup | LoadBalanceGroup
