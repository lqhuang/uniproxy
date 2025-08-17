from __future__ import annotations

from typing import Sequence
from uniproxy.typing import ServerAddress

from attrs import define

from uniproxy.abc import AbstractSurge

from .typing import SurgeGroupType, SurgeProtocolType, SurgeRuleProviderType


@define
class BaseProtocol(AbstractSurge):
    name: str
    server: ServerAddress
    port: int
    type: SurgeProtocolType

    def __str__(self) -> str:
        return str(self.name)

    def __attrs_asdict__(self) -> dict[str, str]:
        raise NotImplementedError

    # @classmethod
    # def from_uniproxy(cls, uniproxy, **kwargs) -> BaseProtocol:
    #     raise NotImplementedError


@define
class BaseProxyProvider(AbstractSurge):
    name: str

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseProxyGroup(AbstractSurge):
    name: str
    proxies: Sequence[ProtocolLike | str]
    type: SurgeGroupType
    # url: str = "http://www.gstatic.com/generate_204"

    @property
    def proxies_opts(self) -> str:
        opts = ", ".join(
            (proxy if isinstance(proxy, str) else proxy.name for proxy in self.proxies)
        )
        return opts

    @property
    def include_other_group(self) -> tuple[BaseProxyGroup, ...]:
        """(Surge) Include other groups in this group."""
        return tuple(
            group for group in self.proxies if isinstance(group, BaseProxyGroup)
        )

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseRule(AbstractSurge): ...


@define
class BaseBasicRule(BaseRule):
    matcher: RuleProviderLike
    policy: ProtocolLike
    # type: str

    def __str__(self) -> str:
        return f"{self.type.upper()},{self.matcher},{self.policy}"  # pyright: ignore[reportAttributeAccessIssue]


@define
class BaseRuleProvider(AbstractSurge):
    name: str
    url: str
    type: SurgeRuleProviderType

    def __str__(self) -> str:
        return str(self.name)


type ProtocolLike = BaseProtocol | BaseProxyProvider | BaseProxyGroup | str
type RuleProviderLike = BaseRuleProvider | str
type RuleLike = BaseRule | str
