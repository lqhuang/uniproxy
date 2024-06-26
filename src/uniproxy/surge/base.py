from __future__ import annotations

from typing import Sequence

from attrs import frozen

from .typing import SurgeGroupType, SurgeProtocolType
from uniproxy.typing import ServerAddress


class AbstractSurge:
    __uniproxy_impl__ = "surge"


@frozen
class BaseProtocol(AbstractSurge):
    name: str
    server: ServerAddress
    port: int
    type: SurgeProtocolType

    def __str__(self) -> str:
        return str(self.name)

    def asdict(self) -> dict[str, str]:
        raise NotImplementedError

    @classmethod
    def from_uniproxy(cls, uniproxy, **kwargs) -> BaseProtocol:
        raise NotImplementedError


@frozen
class BaseProxyGroup(AbstractSurge):
    name: str
    proxies: Sequence[BaseProtocol | BaseProxyGroup]
    type: SurgeGroupType
    # url: str = "http://www.gstatic.com/generate_204"

    def asdict(self) -> dict[str, str]:
        raise NotImplementedError

    @property
    def proxies_opts(self) -> str | None:
        opts = ", ".join((proxy.name for proxy in self.proxies))
        return opts if opts else None

    @property
    def include_other_group(self) -> tuple[BaseProxyGroup, ...]:
        """(Surge) Include other groups in this group."""
        return tuple(
            group for group in self.proxies if isinstance(group, BaseProxyGroup)
        )
