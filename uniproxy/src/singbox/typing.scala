package uniproxy
package singbox
package typing

import com.comcast.ip4s.{Host, Port}

import uniproxy.typing.ALPN

import uniproxy.singbox.shared.Fallback

/** Configuration */
type SingBoxNetwork = Option["tcp" | "udp"]
type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"

/** Inbound */
type TunStack = "system" | "gvisor" | "mixed"
type InboundType = "direct" | "mixed" | "socks" | "http" | "shadowsocks" | "vmess" |
  "trojan" | "naive" | "hysteria" | "shadowtls" | "tuic" | "hysteria2" | "vless" |
  "tun" | "redirect" | "tproxy"

/** Outbound */
type ProtocolOutboundType = "direct" | "block" | "socks" | "http" | "shadowsocks" |
  "vmess" | "trojan" | "wireguard" | "hysteria" | "shadowtls" | "vless" | "tuic" |
  "hysteria2" | "tor" | "ssh" | "dns"
type GroupOutboundType = "selector" | "urltest"
type OutboundType = ProtocolOutboundType | GroupOutboundType

/** DNS */
type DnsReturnCode = "rcode://success" | "rcode://format_error" |
  "rcode://server_failure" | "rcode://name_error" | "rcode://not_implemented" |
  "rcode://refused"
type DomainStrategy = "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"

/** Route */
type RuleSetFormat = "binary" | "source"
type RuleSetType = "local" | "remote"

/** Shared */
type TLSVersion = "1.0" | "1.1" | "1.2" | "1.3"
type SniffProtocol = "http" | "tls" | "quic" | "stun" | "dns" | "bittorrent" | "dtls"
type TransportType = "http" | "ws" | "quic" | "grpc" | "httpupgrade"
type FallbackAlpn = Map[ALPN, Fallback]
