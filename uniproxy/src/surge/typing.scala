// scalafmt: { align.preset = more, indent.ctorSite = 2 }
package uniproxy
package surge
package typing

type ProtocolType = "http" | "https" | "socks5" | "socks5-tls" | "snell" | "ss" |
  "vmess" | "trojan" | "tuic" | "hysteria2" | "wireguard"

type GroupType = "select" | "url-test" | "fallback" | "load-balance" | "external" |
  "subnet" | "smart"

type RuleProviderType = "domain-set" | "rule-set"

type RuleType = "domain" | "domain-suffix" | "domain-keyword" | // Domain Rules
  // IP Rules
  "ip-cidr" | "ip-cidr6" | "ip-asn" | "geoip" |
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
  // External rule
  "rule-set" | "domain-set" |
  // final rule
  "final"
