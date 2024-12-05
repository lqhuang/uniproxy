package uniproxy.clash.typing

type ProtocolType = "http" | "https" | "socks5" | "socks5-tls" | "ss" | "vmess" |
  "trojan" | "tuic" | "juicity" | "wireguard"

type GroupType = "select" | "url-test" | "fallback" | "load-balance" | "external"

type RuleProviderType = "http" | "file"

type RuleProviderBehaviorType = "domain" | "ipcidr" | "classical"

type RuleProviderFormatType = "text" | "yaml" | "mrs"

type RuleType = "domain" | "domain-suffix" | "domain-keyword" |
  "domain-set" | // Domain-based Rule
  // IP-based Rule
  "ip-cidr" | "ip-cidr6" | "geoip" | "ip-asn" |
  // HTTP Rule
  "user-agent" | "url-regex" |
  // Process Rule
  "process-name" |
  // Logical Rule
  "and" | "or" | "not" |
  // Subnet Rule
  "subnet" |
  // Miscellaneous Rule
  "dest-port" | "src-port" | "in-port" | "src-ip" | "protocol" | "script" |
  "cellular-radio" | "device-name" |
  // Ruleset Rule
  "rule-set" |
  // Final Rule
  "final"
