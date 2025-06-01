package uniproxy
package singbox
package typing

import com.comcast.ip4s.{Host, Port}
import upickle.default.ReadWriter

import uniproxy.typing.ALPN

type User = {
  type name = String
  type password = String
}

type Fallback = {
  type server = Host
  type server_port = Port
}

/** Configuration */
// type SingBoxNetwork = "tcp" | "udp"
enum SingBoxNetwork derives ReadWriter {
  case tcp, udp
}

// type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"
enum LogLevel derives ReadWriter {
  case trace, debug, info, warn, error, fatal, panic
}

/** Inbound */
// type TunStack = "system" | "gvisor" | "mixed"
enum TunStack derives ReadWriter {
  case system, gvisor, mixed
}
// type InboundType = "direct" | "mixed" | "socks" | "http" | "shadowsocks" | "vmess" |
//   "trojan" | "naive" | "hysteria" | "shadowtls" | "tuic" | "hysteria2" | "vless" |
//   "tun" | "redirect" | "tproxy"
enum InboundType derives ReadWriter {
  case direct, mixed, socks, http, shadowsocks, vmess, trojan, naive,
    hysteria, shadowtls, tuic, hysteria2, vless, tun, redirect, tproxy
}

/** Outbound */
// type ProtocolOutboundType = "direct" | "block" | "socks" | "http" | "shadowsocks" |
//   "vmess" | "trojan" | "wireguard" | "hysteria" | "shadowtls" | "vless" | "tuic" |
//   "hysteria2" | "tor" | "ssh"
enum ProtocolOutboundType derives ReadWriter {
  case direct, socks, http, shadowsocks, vmess, trojan, hysteria, shadowtls, vless,
    tuic, hysteria2, tor, ssh
}

// type GroupOutboundType = "selector" | "urltest"
enum GroupOutboundType derives ReadWriter {
  case selector, urltest
}
type OutboundType = ProtocolOutboundType | GroupOutboundType

enum EndpointType derives ReadWriter {
  case wireguard, tailscale
}

/** DNS */
// type DnsReturnCode = "rcode://success" | "rcode://format_error" |
//   "rcode://server_failure" | "rcode://name_error" | "rcode://not_implemented" |
//   "rcode://refused"
// type DomainStrategy = "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"
enum DomainStrategy derives ReadWriter {
  case prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only
}
enum DnsServerType derives ReadWriter {
  case legacy, local, hosts, tcp, udp, tls, quic, https, h3, fakeip, tailscale, resolved
}
enum DnsRuleAction derives ReadWriter {
  case route, `route-options`, reject, predefined, fakeip
}

/** Route */
// type RuleSetFormat = "binary" | "source"
enum RuleSetFormat derives ReadWriter {
  case binary, source
}
// type RuleSetType = "local" | "remote"
enum RuleSetType derives ReadWriter {
  case local, remote
}

enum RuleAction derives ReadWriter {
  // Final actions
  case route, reject, `hijack-dns`
  // Intermediate actions
  case `route-options`, `sniff`, `resolve`
}

/** Shared */
// type TLSVersion = "1.0" | "1.1" | "1.2" | "1.3"
enum TLSVersion derives ReadWriter {
  case `1.0`, `1.1`, `1.2`, `1.3`
}
// type SniffProtocol = "http" | "tls" | "quic" | "stun" | "dns" | "bittorrent" | "dtls"
enum SniffProtocol derives ReadWriter {
  case http, tls, quic, stun, dns, bittorrent, dtls
}

// type TransportType = "http" | "ws" | "quic" | "grpc" | "httpupgrade"
enum TransportType derives ReadWriter {
  case http, ws, quic, grpc, httpupgrade
}

type FallbackAlpn = Map[ALPN, Fallback]
