from __future__ import annotations

from typing import Literal

from attrs import define, frozen

from uniproxy.abc import AbstractClash


@frozen
class HealthCheck:
    enable: bool = True
    interval: float = 60
    lazy: bool = True
    url: str = "https://www.gstatic.com/generate_204"


@define
class ProxyProvider(AbstractClash):
    name: str
    type: Literal["http", "file"]

    url: str
    path: str
    interval: int = 3600

    filter: str | None = None  # golang regex
    health_check: HealthCheck | None = HealthCheck()

    def __str__(self) -> str:
        return str(self.name)


@define
class RuleProvider(AbstractClash):
    name: str
    behavior: Literal["domain", "ipcidr", "classical"]
    format: Literal["yaml", "text"]

    url: str
    path: str
    interval: int

    def __str__(self) -> str:
        return str(self.name)
