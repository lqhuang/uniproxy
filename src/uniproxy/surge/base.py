from __future__ import annotations

from typing import Any, ClassVar, Sequence, override
from uniproxy.typing import ServerAddress

from abc import ABC, abstractmethod
from functools import cached_property

from attrs import define

from uniproxy.abc import BaseTaggable
from uniproxy.utils import to_tag


class AbstractSurge(ABC):
    """
    Abstract Clash class

    All Surge classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "surge"


@define
class BaseProtocol(BaseTaggable, AbstractSurge):
    name: str
    server: ServerAddress
    port: int

    # type: SurgeProtocolType

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.name

    @abstractmethod
    def __attrs_asdict__(self) -> dict[str, str]:
        raise NotImplementedError()


@define
class BaseProxyProvider(BaseTaggable, AbstractSurge):
    name: str

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.name


@define
class BaseProxyGroup(BaseTaggable, AbstractSurge):
    name: str
    proxies: Sequence[ProtocolLike | str]
    # type: SurgeGroupType
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

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.name


@define
class BaseRule(BaseTaggable, AbstractSurge):
    @cached_property
    @override
    def to_tag(self) -> str:
        # pyrefly: ignore [missing-attribute]
        return f"{self.type},{self.matcher},{to_tag(self.policy)}"


type ProtocolLike = BaseProtocol | BaseProxyProvider | BaseProxyGroup | str
type RuleLike = BaseRule | str
