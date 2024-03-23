from __future__ import annotations

from enum import StrEnum


class ProtocolType(StrEnum):
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


class Network(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    TCP_AND_UDP = "tcp_and_udp"
