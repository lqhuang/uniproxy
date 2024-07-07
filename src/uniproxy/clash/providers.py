from __future__ import annotations

from typing import Literal

from attrs import define, frozen


from .base import BaseProxyProvider, BaseRuleProvider
from uniproxy.providers import UniproxyProxyProvider


@define
class ClashProxyProvider(BaseProxyProvider):

    @classmethod
    def from_uniproxy(
        cls, provider: UniproxyProxyProvider, **kwargs
    ) -> ClashProxyProvider:
        return cls(
            name=provider.name,
            type=provider.type,
            url=provider.url,
            path=provider.path,
            interval=provider.interval,
            filter=provider.filter,
            health_check=provider.health_check,
        )

    def to_uniproxy(self) -> UniproxyProxyProvider:
        return self.to_uniproxy()


@frozen
class HealthCheck:
    enable: bool = True
    interval: float = 60
    lazy: bool = True
    url: str = "https://www.gstatic.com/generate_204"


@define
class ProxyProvider(BaseProxyProvider):
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
class RuleProvider(BaseRuleProvider):
    name: str
    behavior: Literal["domain", "ipcidr", "classical"]
    format: Literal["yaml", "text"]

    url: str
    path: str
    interval: int

    def __str__(self) -> str:
        return str(self.name)
