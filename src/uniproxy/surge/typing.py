from __future__ import annotations

from typing import Literal, TypeAlias

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
    "wireguard",
]
SurgeGroupType = Literal[
    "select", "url-test", "fallback", "load-balance", "external", "subnet", "smart"
]

SurgeRuleProviderType = Literal["domain-set", "rule-set"]

_ProtocolOptions: TypeAlias = dict[str, str | None]
