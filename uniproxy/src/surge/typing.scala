package uniproxy.surge.typing

type ProtocolType = "http" | "https" | "socks5" | "socks5-tls" | "snell" |
  "ss" | "vmess" | "trojan" | "tuic" | "hysteria2" | "wireguard"

type GroupType = "select" | "url-test" | "fallback" | "load-balance" |
  "external" | "subnet" | "smart"

type RuleProviderType = "domain-set" | "rule-set"

// _ProtocolOptions: TypeAlias = dict[str, str | None]
