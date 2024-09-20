from __future__ import annotations

from typing import Literal

from attrs import define, field, frozen

from uniproxy.providers import ProxyProvider as UniproxyProxyProvider

from .base import BaseProxyProvider, BaseRuleProvider
from .typing import RuleProviderBehaviorType, RuleProviderFormatType, RuleProviderType


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
    type: RuleProviderType
    format: RuleProviderFormatType
    behavior: RuleProviderBehaviorType

    url: str | None = None
    path: str | None = None
    interval: int | None = None

    def __attrs_post_init__(self) -> None:
        if self.url is None and self.path is None:
            raise ValueError("Either 'url' or 'path' must be provided")
        match self.format:
            # https://wiki.metacubex.one/config/rule-providers/
            case "yaml":
                ext = "yaml"
            case "text":
                ext = "txt"
            case "mrs":
                ext = "mrs"
            case _:
                raise ValueError(f"Unsupported format: {self.format}")
        if self.path is None:
            self.path = f"./rule-providers/{self.name}.{ext}"


@define
class DomainRuleProvider(RuleProvider):
    name: str
    type: RuleProviderType
    format: Literal["yaml", "text"]

    url: str | None = None
    path: str | None = None
    interval: int | None = None

    behavior: Literal["domain"] = "domain"


@define
class IPCidrRuleProvider(RuleProvider):
    name: str
    type: RuleProviderType
    format: Literal["yaml", "text", "mrs"]

    url: str | None = None
    path: str | None = None
    interval: int | None = None

    behavior: Literal["ipcidr"] = "ipcidr"


@define
class ClassicalRuleProvider(RuleProvider):
    name: str
    type: RuleProviderType
    format: Literal["yaml", "text", "mrs"]

    url: str | None = None
    path: str | None = None
    interval: int | None = None

    behavior: Literal["classical"] = "classical"
