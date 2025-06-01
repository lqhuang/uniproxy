package uniproxy
package typing

import com.comcast.ip4s.{Cidr, Ipv4Address, Ipv6Address}
import upickle.default.ReadWriter
import upickle.default.ReadWriter.merge

enum Backend:
  case surge, clash, singbox

enum Network:
  case tcp, udp, tcp_and_udp

type NetworkCIDR = Cidr[Ipv4Address] | Cidr[Ipv6Address]
given networkCidrReadWriter: ReadWriter[NetworkCIDR] = merge(
  implicitly[ReadWriter[Cidr[Ipv4Address]]],
  implicitly[ReadWriter[Cidr[Ipv6Address]]],
)

enum ShadowsocksCipher:
  case `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`,
    `blake3-aes-128-gcm`, `blake3-aes-256-gcm`, `blake3-chacha20-poly1305`,
    `blake3-chacha8-poly1305`

enum VmessCipher:
  case none, auto, zero, `aes-128-gcm`, `chacha20-poly1305`

enum VmessTransportType:
  case http, ws, grpc, h2

enum ALPN:
  case `http/1.1`, h2, h3

enum ProtocolType:
  case http, https, http2, quic, socks4, socks5, `socks5-tls`,
    shadowsocks, vmess, trojan, snell, naive, tuic, wireguard

enum GroupType:
  case select, urltest, fallback, loadbalance, external, subnet

enum BasicRuleType:
  // Domain Rules
  case domain
  case `domain-suffix`
  case `domain-keyword`
  // IP Rules
  case `ip-cidr`
  case `ip-cidr6`
  case `ip-asn`
  case geoip
  // HTTP Rule
  case `user-agent`
  case `url-regex`
  // Process Rule
  case `process-name`
  // Logical Rule
  case and
  case or
  case not
  // Subnet Rule
  case subnet
  // Miscellaneous Rule
  case `dest-port`
  case `src-port`
  case `in-port`
  case `src-ip`
  case protocol
  case script
  case `cellular-radio`
  case `device-name`
  // External rule
  case `rule-set`
  case `domain-set`
  // Final Rule
  case `final`

enum GroupRuleType:
  case `domain-group`
  case `domain-suffix-group`
  case `domain-keyword-group`
  case `ip-cidr-group`
  case `ip-cidr6-group`

type RuleType = BasicRuleType | GroupRuleType
