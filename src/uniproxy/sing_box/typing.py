from typing import Literal

from enum import StrEnum

SingBoxNetwork = Literal["tcp", "udp", ""]


InboundType = Literal[
    "direct",
    "mixed",
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "trojan",
    "naive",
    "hysteria",
    "shadowtls",
    "tuic",
    "hysteria2",
    "vless",
    "tun",
    "redirect",
    "tproxy",
]

OutboundType = Literal[
    "direct",
    "block",
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "trojan",
    "wireguard",
    "hysteria",
    "shadowtls",
    "vless",
    "tuic",
    "hysteria2",
    "tor",
    "ssh",
    "dns",
    "selector",
    "urltest",
]
