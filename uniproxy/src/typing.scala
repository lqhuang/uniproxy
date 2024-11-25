package uniproxy
package typing

type Backend = "surge" | "clash" | "singbox"

type Network = "tcp" | "udp" | "tcp_and_udp"

type ShadowsocksCipher = "aes-128-gcm" | "aes-256-gcm" |
  "chacha20-ietf-poly1305" | "blake3-aes-128-gcm" | "blake3-aes-256-gcm" |
  "blake3-chacha20-poly1305" | "blake3-chacha8-poly1305"

type VmessCipher = "none" | "auto" | "zero" | "AES-128-GCM" |
  "CHACHA20-POLY1305"
type VmessTransportType = "http" | "ws" | "grpc" | "h2"

type ALPN = "http/1.1" | "h2" | "h3"

type ProtocolType = "http" | "https" | "http2" | "quic" | "socks4" | "socks5" |
  "socks5-tls" | "shadowsocks" | "vmess" | "trojan" | "snell" | "naive" |
  "tuic" | "wireguard"
type GroupType =
  "select" | "urltest" | "fallback" | "loadbalance" | "external" | "subnet"

type BasicRuleType =
  // Domain Rules
  "domain" | "domain-suffix" | "domain-keyword" |
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
    "rule-set" | "domain-set"
type GroupRuleType = "domain-group" | "domain-suffix-group" |
  "domain-keyword-group" | "ip-cidr-group" | "ip-cidr6-group"
type RuleType = BasicRuleType | GroupRuleType | "final"
