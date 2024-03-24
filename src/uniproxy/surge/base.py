from __future__ import annotations

from typing import Literal

from abc import ABC


class AbstractSurge(ABC):
    __backend__ = "surge"


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


class BaseProtocol(AbstractSurge):
    name: str
    type: ProtocolType

    def __str__(self) -> str:
        return str(self.name)
