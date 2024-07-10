from __future__ import annotations

from typing import Literal, Mapping, Sequence, TypeAlias

from attrs import define

from .base import (
    AbstractClash,
    BaseProtocol,
    BaseProxyGroup,
    BaseRule,
    BaseProxyProvider,
)
from .rules import RuleProvider

Hosts: TypeAlias = Mapping[str, str]
Proxies: TypeAlias = Sequence[BaseProtocol]
ProxyProviders: TypeAlias = Sequence[BaseProxyProvider]
ProxyGroups: TypeAlias = Sequence[BaseProxyGroup]
RuleProviders: TypeAlias = Sequence[RuleProvider]
Rules: TypeAlias = Sequence[BaseRule]

Mode = Literal["rule", "global", "direct"]
LogLevelType = Literal["silent", "info", "warning", "error", "debug"]


@define
class ClashConfig(AbstractClash):
    mode: Mode
    log_level: LogLevelType
    ipv6: bool

    port: int
    socks_port: int
    redir_port: int
    mixed_port: int

    allow_lan: bool
    bind_address: str
    external_controller: str

    # dns: Dns
    # tun: Tun
    # hosts: Hosts
    proxies: Proxies
    proxy_providers: ProxyProviders
    proxy_groups: ProxyGroups
    rule_providers: RuleProviders
    rules: Rules
