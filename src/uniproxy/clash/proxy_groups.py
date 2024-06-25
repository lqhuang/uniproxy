from __future__ import annotations

from typing import Literal


from attrs import frozen

from .base import BaseProxyGroup


@frozen
class SelectGroup(BaseProxyGroup):
    type: Literal["select"] = "select"


@frozen
class UrlTestGroup(BaseProxyGroup):
    tolerance: float = 300  # milliseconds

    type: Literal["url-test"] = "url-test"


@frozen
class FallBackGroup(BaseProxyGroup):
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds

    type: Literal["fallback"] = "fallback"


@frozen
class LoadBalanceGroup(BaseProxyGroup):
    strategy: Literal["consistent-hashing", "round-robin"] | None = None

    type: Literal["load-balance"] = "load-balance"
