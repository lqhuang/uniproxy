from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

from attrs import define

from .base import (
    AbstractMihomo,
    BaseProtocol,
    BaseProxyGroup,
    BaseProxyProvider,
    BaseRule,
)
from .providers import RuleProvider

type Hosts = Mapping[str, str]
type Proxies = Sequence[BaseProtocol]
type ProxyProviders = Sequence[BaseProxyProvider]
type ProxyGroups = Sequence[BaseProxyGroup]
type RuleProviders = Sequence[RuleProvider]
type Rules = Sequence[BaseRule]

Mode = Literal["rule", "global", "direct"]
LogLevelType = Literal["silent", "info", "warning", "error", "debug"]


@define
class ClashConfig(AbstractMihomo):
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
