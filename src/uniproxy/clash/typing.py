from typing import Literal

ProtocolType = Literal[
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
GroupType = Literal["select", "url-test", "fallback", "load-balance", "external"]

RuleProviderType = Literal["http", "file"]
RuleProviderBehaviorType = Literal[
    "domain",
    "ipcidr",
    "classical",
]
RuleProviderFormatType = Literal["text", "yaml", "mrs"]

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
    "rule-set",
]
