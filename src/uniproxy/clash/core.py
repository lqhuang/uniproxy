from typing import Iterable, Literal, TypeAlias

from .abc import AbstractClash

Hosts: TypeAlias = dict[str, str]
Proxies: TypeAlias = Iterable[Proxy]
ProxyProviders: TypeAlias = list[ProxyProvider]
ProxyGroups: TypeAlias = list[ProxyGroup]
RuleProviders: TypeAlias = list[RuleProvider]
Rules: TypeAlias = list[Rule]

LogLevelType = Literal["silent", "info", "warning", "error", "debug"]


class ClashConfig(AbstractClash):
    mode: Literal["Rule", "Global", "Direct"]
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
