from __future__ import annotations

from typing import Literal, Sequence

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
