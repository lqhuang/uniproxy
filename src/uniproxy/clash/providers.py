from __future__ import annotations

from typing import Literal

from attrs import define, field, frozen

from uniproxy.providers import ProxyProvider as UniproxyProxyProvider

from .base import BaseProxyProvider, BaseRuleProvider


@frozen
class HealthCheck:
    enable: bool = True
    interval: float = 120
    lazy: bool = True
    # url: str = "https://www.gstatic.com/generate_204"


@define
class ProxyProvider(BaseProxyProvider):
    name: str = field(metadata={"exclude": True})
    type: Literal["http", "file"]

    url: str
    path: str
    interval: float | None = None

    filter: str | None = None  # golang regex
    health_check: HealthCheck | None = HealthCheck()

    def __str__(self) -> str:
        return str(self.name)

    @classmethod
    def from_uniproxy(cls, provider: UniproxyProxyProvider, **kwargs) -> ProxyProvider:
        if provider.path is None:
            path = f"./proxy-providers/{provider.name}.yaml"
        else:
            path = provider.path

        return cls(
            name=provider.name,
            type="http",
            url=provider.url,
            path=path,
            interval=provider.interval,
            filter=provider.filter,
            health_check=HealthCheck() if provider.health_check else None,
        )

    def to_uniproxy(self) -> UniproxyProxyProvider:
        return self.to_uniproxy()


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
