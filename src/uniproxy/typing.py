from __future__ import annotations

from typing import Literal, Union

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

type Backend = Literal["surge", "clash", "sing-box"]

type ServerAddress = str | IPv4Address | IPv6Address
type IPAddress = str | IPv4Address | IPv6Address
type NetworkCIDR = str | IPv4Network | IPv6Network


type ProtocolType = Literal[
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
    "anytls",
]
type Network = Literal["tcp", "udp", "tcp_and_udp"]


type ShadowsocksCipher = Literal[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
]
type VmessCipher = Literal["none", "auto", "zero", "aes-128-gcm", "chacha20-poly1305"]
type VmessTransportType = Literal["http", "ws", "grpc", "h2"]


type GroupType = Literal[
    "select", "url-test", "fallback", "load-balance", "external", "subnet"
]


type BasicRuleType = Literal[
    # Domain-based Rule
    "domain",
    "domain-suffix",
    "domain-keyword",
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
    # Final Rule
]
BASIC_RULES = frozenset((
    # Domain-based Rule
    "domain",
    "domain-suffix",
    "domain-keyword",
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
    # Final Rule
))

# # External Rule
# ExternalRuleType = Literal["rule-set", "domain-set"]
# EXTERNAL_RULES = set(("rule-set", "domain-set"))

# IP-based Rule
type BasicNoResolableRuleType = Literal["ip-cidr", "ip-cidr6", "ip-asn", "geoip"]
BASIC_NO_RESOLABLE_RULES = set((
    # IP-based Rule
    "ip-cidr",
    "ip-cidr6",
    "ip-asn",
    "geoip",
))

# Group Rule
type GroupRuleType = Literal[
    "domain-group", "domain-suffix-group", "domain-keyword-group"
]
GROUP_RULES = set((
    "domain-group",
    "domain-suffix-group",
    "domain-keyword-group",
    "ip-cidr-group",
    "ip-cidr6-group",
))
type GroupNoResolvableRuleType = Literal["ip-cidr-group", "ip-cidr6-group"]
GROUP_NO_RESOLVABLE_RULES = set(("ip-cidr-group", "ip-cidr6-group"))

type FinalRuleType = Literal["final"]

type UniproxyRuleType = (
    BasicRuleType | BasicNoResolableRuleType | GroupRuleType | FinalRuleType
)


type AlpnType = Literal["http/1.1", "h2", "h3"]
