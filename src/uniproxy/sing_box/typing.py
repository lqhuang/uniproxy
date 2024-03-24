from typing import Literal

from enum import StrEnum

SingBoxNetwork = Literal["tcp", "udp", ""]


class SingBoxNetworkEnum(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    TCP_AND_UDP = ""


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


class OutboundTypeEnum(StrEnum):
    DIRECT = "direct"
    BLOCK = "block"
    SOCKS = "socks"
    HTTP = "http"
    SHADOWSOCKS = "shadowsocks"
    VMESS = "vmess"
    TROJAN = "trojan"
    WIREGUARD = "wireguard"
    HYSTERIA = "hysteria"
    SHADOWTLS = "shadowtls"
    VLESS = "vless"
    TUIC = "tuic"
    HYSTERIA2 = "hysteria2"
    TOR = "tor"
    SSH = "ssh"
    DNS = "dns"
    SELECTOR = "selector"
    URLTEST = "urltest"
