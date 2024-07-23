from __future__ import annotations

from typing import Literal, Sequence

import gc

from attrs import define, fields

from uniproxy._helpers import (
    _map_from_uniproxy,
    merge_pairs_by_key,
    split_uniproxy_protocol_like,
)
from uniproxy.clash.protocols import ClashProtocol
from uniproxy.clash.providers import ProxyProvider as ClashProxyProvider
from uniproxy.protocols import UniproxyProtocol
from uniproxy.proxy_groups import FallBackGroup as UniproxyFallBackGroup
from uniproxy.proxy_groups import LoadBalanceGroup as UniproxyLoadBalanceGroup
from uniproxy.proxy_groups import SelectGroup as UniproxySelectGroup
from uniproxy.proxy_groups import UniproxyProxyGroup
from uniproxy.proxy_groups import UrlTestGroup as UniproxyUrlTestGroup

from .base import BaseProtocol, BaseProxyGroup, BaseProxyProvider


def _split_proxy_and_provider(proxies: Sequence[UniproxyProtocol]) -> tuple[
    list[BaseProxyGroup | BaseProtocol],
    list[BaseProxyProvider],
]:
    uni_protocols, uni_providers, uni_groups = split_uniproxy_protocol_like(proxies)

    idx_protocols = _map_from_uniproxy(uni_protocols, ClashProtocol)
    idx_providers = _map_from_uniproxy(uni_providers, ClashProxyProvider)
    idx_groups = _map_from_uniproxy(uni_groups, ClashProxyGroup)

    proxies = merge_pairs_by_key(idx_protocols, idx_groups)  # type: ignore
    providers = merge_pairs_by_key(idx_providers)

    return proxies, providers  # type: ignore


@define
class ClashProxyGroup(BaseProxyGroup):

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyProxyGroup, **kwargs) -> ClashProxyGroup:
        gc.collect(1)
        for subcls in cls.__subclasses__():
            proto_type = fields(subcls).type.default
            if proto_type == protocol.type:
                inst = subcls.from_uniproxy(protocol)
                break
        else:
            implemented = tuple(
                fields(subcls).type.default for subcls in cls.__subclasses__()
            )
            raise NotImplementedError(
                f"Unknown protocol type: '{protocol.type}' for implemented ClashProxyGroup subclasses {implemented}"
            )

        return inst

    def to_uniproxy(self, **kwargs) -> UniproxyProxyGroup:
        return self.to_uniproxy()

    def __str__(self) -> str:
        return str(self.name)


@define
class SelectGroup(ClashProxyGroup):
    type: Literal["select"] = "select"

    @classmethod
    def from_uniproxy(cls, protocol: UniproxySelectGroup, **kwargs) -> SelectGroup:
        proxies, providers = _split_proxy_and_provider(
            protocol.proxies  # pyright: ignore[reportArgumentType]
        )

        return cls(
            name=protocol.name,
            proxies=proxies if proxies else None,
            use=providers if providers else None,
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
        )


@define
class UrlTestGroup(ClashProxyGroup):
    tolerance: float = 300  # milliseconds
    type: Literal["url-test"] = "url-test"

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyUrlTestGroup, **kwargs) -> UrlTestGroup:
        proxies, providers = _split_proxy_and_provider(
            protocol.proxies  # pyright: ignore[reportArgumentType]
        )

        return cls(
            name=protocol.name,
            proxies=proxies if proxies else None,
            use=providers if providers else None,
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
            tolerance=protocol.tolerance,
        )


@define
class FallBackGroup(ClashProxyGroup):
    timeout: float = 5  # seconds

    type: Literal["fallback"] = "fallback"

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyFallBackGroup, **kwargs) -> FallBackGroup:
        proxies, providers = _split_proxy_and_provider(
            protocol.proxies  # pyright: ignore[reportArgumentType]
        )
        return cls(
            name=protocol.name,
            proxies=proxies if proxies else None,
            use=providers if providers else None,
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
            timeout=protocol.timeout,
        )


@define
class LoadBalanceGroup(ClashProxyGroup):
    strategy: Literal["consistent-hashing", "round-robin"] | None = None

    type: Literal["load-balance"] = "load-balance"

    @classmethod
    def from_uniproxy(
        cls, protocol: UniproxyLoadBalanceGroup, **kwargs
    ) -> LoadBalanceGroup:
        proxies, providers = _split_proxy_and_provider(
            protocol.proxies  # pyright: ignore[reportArgumentType]
        )
        return cls(
            name=protocol.name,
            proxies=proxies if proxies else None,
            use=providers if providers else None,
            disable_udp=protocol.network == "tcp",
            url=protocol.url,
            interval=protocol.interval,
            strategy=protocol.strategy,
        )
