from __future__ import annotations

from typing import Literal

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

type Backend = Literal["surge", "clash", "sing-box"]

type ServerAddress = str | IPv4Address | IPv6Address

type IPAddress = str | IPv4Address | IPv6Address

type NetworkCIDR = str | IPv4Network | IPv6Network

type AlpnType = Literal["http/1.1", "h2", "h3"]

type ShadowsocksCipher = Literal[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
]
