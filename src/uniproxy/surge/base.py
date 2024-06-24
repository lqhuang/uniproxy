from __future__ import annotations

from typing import Literal, Iterable

from abc import ABC


class AbstractSurge(ABC):
    __uniproxy_impl__ = "surge"


SurgeProtocolType = Literal[
    "http",
    "https",
    "socks5",
    "socks5-tls",
    "snell",
    "ss",
    "vmess",
    "trojan",
    "tuic",
    "hysteria2",
]


class BaseProtocol(AbstractSurge):
    name: str
    type: SurgeProtocolType

    def __str__(self) -> str:
        return str(self.name)


SurgeGroupType = Literal[
    "select", "url-test", "fallback", "load-balance", "external", "subnet", "smart"
]


class BaseProxyGroup(AbstractSurge):
    name: str
    proxies: Iterable[BaseProtocol | BaseProxyGroup]
    type: SurgeGroupType
    # url: str = "http://www.gstatic.com/generate_204"

    def as_dict(self) -> dict[str, str]:
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
