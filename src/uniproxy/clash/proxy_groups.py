from __future__ import annotations

from typing import Literal

from attrs import define

from .base import BaseProxyGroup


@define
class SelectGroup(BaseProxyGroup):
    type: Literal["select"] = "select"


@define
class UrlTestGroup(BaseProxyGroup):
    tolerance: float = 300  # milliseconds

    type: Literal["url-test"] = "url-test"


@define
class FallBackGroup(BaseProxyGroup):
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds

    type: Literal["fallback"] = "fallback"


@define
class LoadBalanceGroup(BaseProxyGroup):
    strategy: Literal["consistent-hashing", "round-robin"] | None = None

    type: Literal["load-balance"] = "load-balance"
