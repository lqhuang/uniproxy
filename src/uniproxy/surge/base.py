from __future__ import annotations

from typing import Literal

from abc import ABC


class AbstractSurge(ABC):
    __uniproxy_impl__ = "surge"


ProtocolType = Literal[
    "http",
    "https",
    "socks5",
    "socks5-tls",
    "snell",
    "ss",
    "vmess",
    "trojan",
    "tuic",
    "hysteria",
]


class BaseSurgeProtocol(AbstractSurge):
    name: str
    type: ProtocolType

    def __str__(self) -> str:
        return str(self.name)
