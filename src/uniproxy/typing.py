from __future__ import annotations

from enum import StrEnum


class ProtocolType(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    SOCKS5_TLS = "socks5-tls"

    SHADOWSOCKS = "ss"
    VMESS = "vmess"
    TROJAN = "trojan"
    SNELL = "snell"
    TUIC = "tuic"

    QUIC = "quic"
    WIREGUARD = "wireguard"
