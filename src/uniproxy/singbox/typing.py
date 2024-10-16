from __future__ import annotations

from typing import Literal, Mapping, Protocol
from uniproxy.typing import ALPN, ServerAddress

SingBoxNetwork = Literal["tcp", "udp", None]
LogLevel = Literal["trace", "debug", "info", "warn", "error", "fatal", "panic"]

TunStack = Literal["system", "gvisor", "mixed"]
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
ProtocolOutboundType = Literal[
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
]
GroupOutboundType = Literal["selector", "urltest"]
OutboundType = ProtocolOutboundType | GroupOutboundType

TLSVersion = Literal["1.0", "1.1", "1.2", "1.3"]

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
SniffProtocol = Literal["http", "tls", "quic", "stun", "dns", "bittorrent", "dtls"]
TransportType = Literal["http", "ws", "quic", "grpc", "httpupgrade"]

# Route
RuleSetType = Literal["local", "remote"]


class Fallback(Protocol):
    server: ServerAddress
    server_port: int


FallbackAlpn = Mapping[ALPN, Fallback]
