from __future__ import annotations

from typing import Literal

SingBoxNetwork = Literal["tcp", "udp"]

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

# DNS
DnsReturnCode = Literal[
    "rcode://success",
    "rcode://format_error",
    "rcode://server_failure",
    "rcode://name_error",
    "rcode://not_implemented",
    "rcode://refused",
]
DnsStrategy = Literal["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"]

# Shared
SniffProtocol = Literal["HTTP", "TLS", "QUIC", "STUN", "DNS"]
TransportType = Literal["http", "ws", "quic", "grpc", "httpupgrade"]
