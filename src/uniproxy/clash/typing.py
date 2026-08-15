from __future__ import annotations

from typing import Literal

type ProtocolType = Literal[
    "http",
    "https",
    "socks5",
    "socks5-tls",
    "ss",
    "vmess",
    "trojan",
    "tuic",
    "juicity",
    "wireguard",
]
type GroupType = Literal["select", "url-test", "fallback", "load-balance", "external"]

type RuleProviderType = Literal["http", "file"]
type RuleProviderBehaviorType = Literal["domain", "ipcidr", "classical"]
type RuleProviderFormatType = Literal["text", "yaml", "mrs"]

type RuleType = Literal[
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
    "rule-set",
    # Final Rule
    "final",
]
