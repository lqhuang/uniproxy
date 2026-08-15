from __future__ import annotations

from typing import Literal

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
