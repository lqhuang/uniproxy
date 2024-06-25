from __future__ import annotations

from typing import Literal

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

SurgeGroupType = Literal[
    "select", "url-test", "fallback", "load-balance", "external", "subnet", "smart"
]
