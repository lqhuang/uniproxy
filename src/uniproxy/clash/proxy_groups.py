from __future__ import annotations

from typing import Literal

from attrs import define

from .base import BaseProxyGroup


@define
class ClashProxyGroup(BaseProxyGroup): ...


@define
class SelectGroup(ClashProxyGroup):

    disable_udp: bool = False

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 600  # seconds
    lazy: bool = True

    # timeout: float = 5  # seconds
    # filter: str | None = None

    type: Literal["select"] = "select"


@define
class UrlTestGroup(ClashProxyGroup):

    disable_udp: bool = False

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 600  # seconds
    lazy: bool = True

    # timeout: float = 5  # seconds
    # filter: str | None = None

    tolerance: float = 300  # milliseconds
    type: Literal["url-test"] = "url-test"


@define
class FallBackGroup(ClashProxyGroup):
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds

    type: Literal["fallback"] = "fallback"


@define
class LoadBalanceGroup(ClashProxyGroup):
    strategy: Literal["consistent-hashing", "round-robin"] | None = None

    type: Literal["load-balance"] = "load-balance"
