from __future__ import annotations

from typing import Literal

from enum import StrEnum


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


class NetworkEnum(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    TCP_AND_UDP = "tcp_and_udp"


Network = Literal["tcp", "udp", "tcp_and_udp"]
