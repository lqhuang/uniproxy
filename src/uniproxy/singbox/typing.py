from __future__ import annotations

from typing import Literal, Mapping, Protocol
from uniproxy.typing import AlpnType, ServerAddress

type SingBoxNetwork = Literal["tcp", "udp"]
type LogLevel = Literal["trace", "debug", "info", "warn", "error", "fatal", "panic"]

type TunStack = Literal["system", "gvisor", "mixed"]
type InboundType = Literal[
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
type ProtocolOutboundType = Literal[
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
type GroupOutboundType = Literal["selector", "urltest"]
type OutboundType = ProtocolOutboundType | GroupOutboundType

type TLSVersion = Literal["1.0", "1.1", "1.2", "1.3"]


# Shared
SNIFF_PROTOCOLS = {
    "http",
    "tls",
    "quic",
    "stun",
    "dns",
    "bittorrent",
    "dtls",
    "ssh",
    "rdp",
    "ntp",
}
type SniffProtocol = Literal[
    "http", "tls", "quic", "stun", "dns", "bittorrent", "dtls", "ssh", "rdp", "ntp"
]
type TransportType = Literal["http", "ws", "quic", "grpc", "httpupgrade"]

# Route
type RuleSetType = Literal["local", "remote"]
# Route
type RuleSetSourceType = Literal["source", "binary"]


class Fallback(Protocol):
    server: ServerAddress
    server_port: int


type FallbackAlpn = Mapping[AlpnType, Fallback]
