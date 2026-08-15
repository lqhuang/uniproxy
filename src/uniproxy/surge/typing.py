from __future__ import annotations

from typing import Literal

type SurgeProtocolType = Literal[
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

type SurgeRuleProviderType = Literal["domain-set", "rule-set"]

type _ProtocolOptions = dict[str, str | None]
