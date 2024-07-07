from __future__ import annotations

from typing import Literal

from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

ServerAddress = str | IPv4Address | IPv6Address

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


class ProtocolTypeEnum(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    HTTP2 = "http2"
    QUIC = "quic"

    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    SOCKS5_TLS = "socks5-tls"

    SHADOWSOCKS = "shadowsocks"
    VMESS = "vmess"
    TROJAN = "trojan"
    SNELL = "snell"
    NAIVE = "naive"
    TUIC = "tuic"
    WIREGUARD = "wireguard"


Network = Literal["tcp", "udp", "tcp_and_udp"]


class NetworkEnum(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    TCP_AND_UDP = "tcp_and_udp"


ShadowsocksCipher = Literal[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
]


class ShadowsocksCipherEnum(StrEnum):
    AEAD_AES_128_GCM = "aes-128-gcm"
    ADAD_AES_256_GCM = "aes-256-gcm"
    AEAD_CHACHA20_IETF_POLY1305 = "chacha20-ietf-poly1305"
    AEAD_2022_BLAKE3_AES_128_GCM = "2022-blake3-aes-128-gcm"
    AEAD_2022_BLAKE3_AES_256_GCM = "2022-blake3-aes-256-gcm"
    AEAD_2022_BLAKE3_CHACHA20_POLY1305 = "2022-blake3-chacha20-poly1305"
    AEAD_2022_BLAKE3_CHACHA8_POLY1305 = "2022-blake3-chacha8-poly1305"


VmessCipher = Literal["none", "auto", "zero", "aes-128-gcm", "chacha20-poly1305"]


class VmessCipherEnum(StrEnum):
    NONE = "none"
    AUTO = "auto"
    ZERO = "zero"
    AES_128_GCM = "aes-128-gcm"
    CHACHA20_POLY1305 = "chacha20-pol1305"


VmessTransport = Literal["http", "ws", "grpc", "h2"]


class VmessTransportEnum(StrEnum):
    HTTP = "http"
    WS = "ws"
    GRPC = "grpc"
    H2 = "h2"


GroupType = Literal[
    "select", "url-test", "fallback", "load-balance", "external", "subnet"
]


RuleType = Literal[
    # Domain-based Rule
    "domain",
    "domain-suffix",
    "domain-keyword",
    "domain-set",
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
    # Ruleset
    # "rule-set",
    # Final Rule
    "final",
]
