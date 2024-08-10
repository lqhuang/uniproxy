from __future__ import annotations

from typing import Literal

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

ServerAddress = str | IPv4Address | IPv6Address
IPAddress = str | IPv4Address | IPv6Address
NetworkCIDR = str | IPv4Network | IPv6Network


ProtocolType = Literal[
    "http",
    "https",
    "http2",
    "quic",
    "socks4",
    "socks5",
    "socks5-tls",
    "shadowsocks",
    "vmess",
    "trojan",
    "snell",
    "naive",
    "tuic",
    "wireguard",
]
Network = Literal["tcp", "udp", "tcp_and_udp"]


ShadowsocksCipher = Literal[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
]
VmessCipher = Literal["none", "auto", "zero", "aes-128-gcm", "chacha20-poly1305"]
VmessTransport = Literal["http", "ws", "grpc", "h2"]


GroupType = Literal[
    "select", "url-test", "fallback", "load-balance", "external", "subnet"
]
RuleType = Literal[
    # Domain-based Rule
    "domain",
    "domain-suffix",
    "domain-keyword",
    # IP-based Rule
    "ip-cidr",
    "ip-cidr6",
    "geoip",
    # HTTP Rule
    "user-agent",
    "url-regex",
    # Process Rule
    "process-name",
    # Logical Rule
    "and",
    "or",
    "not",
    # Subnet Rule
    "subnet",
    # Miscellaneous Rule
    "dest-port",
    "src-port",
    "in-port",
    "src-ip",
    "protocol",
    "script",
    "cellular-radio",
    "device-name",
    # External Rule
    "rule-set",
    "domain-set",
    # Final Rule
    "final",
    # Group Rule
    "domain-group",
    "domain-suffix-group",
    "domain-keyword-group",
    "ip-cidr-group",
    "ip-cidr6-group",
]


ALPN = Literal["http/1.1", "h2", "h3"]
