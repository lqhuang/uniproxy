package uniproxy.singbox
package shared

import com.comcast.ip4s.{Host, Port}
import com.comcast.ip4s.{Hostname, Ipv4Address, Ipv6Address}

import uniproxy.typing.ALPN
import uniproxy.singbox.abc.{AbstractSingBox, InboundLike, OutboundLike}
import uniproxy.singbox.typing.{DomainStrategy, TLSVersion, TransportType}

/**
 * ```json
 * {
 *   "listen": "::",
 *   "listen_port": 5353,
 *   "tcp_fast_open": false,
 *   "tcp_multi_path": false,
 *   "udp_fragment": false,
 *   "udp_timeout": "5m",
 *   "detour": "another-in",
 *   "sniff": false,
 *   "sniff_override_destination": false,
 *   "sniff_timeout": "300ms",
 *   "domain_strategy": "prefer_ipv6",
 *   "udp_disable_domain_unmapping": false
 * }
 * ```
 */
trait ListenFieldsMixin:
  /**
   * Required
   *
   * Listen address.
   */
  val listen: Host

  /** Listen port. */
  val listen_port: Port

  /** Enable TCP Fast Open. */
  val tcp_fast_open: Option[Boolean]

  /** Enable TCP Multi Path. */
  val tcp_multi_path: Option[Boolean]

  /** Enable UDP fragmentation. */
  val udp_fragment: Option[Boolean]

  /**
   * UDP NAT expiration time in seconds.
   *
   * `5m` is used by default.
   */
  val udp_timeout: Option[String]

  /**
   * If set, connections will be forwarded to the specified inbound.
   *
   * Requires target inbound support, see Injectable.
   */
  val detour: Option[OutboundLike]

  /** Enable sniffing. */
  @deprecated
  val sniff: Option[Boolean] = None

  /**
   * Override the connection destination address with the sniffed domain.
   *
   * If the domain name is invalid (like tor), this will not work.
   */
  @deprecated
  val sniff_override_destination: Option[Boolean] = None

  /**
   * Timeout for sniffing.
   *
   * 300ms is used by default.
   */
  @deprecated
  val sniff_timeout: Option[String] = None

  /**
   * One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
   *
   * If set, the requested domain name will be resolved to IP before routing.
   *
   * If `sniff_override_destination` is in effect, its value will be taken as a
   * fallback.
   */
  @deprecated
  val domain_strategy: Option[DomainStrategy] = None

  /**
   * If enabled, for UDP proxy requests addressed to a domain, the original packet
   * address will be sent in the response instead of the mapped domain.
   *
   * This option is used for compatibility with clients that do not support receiving
   * UDP packets with domain addresses, such as Surge.
   */
  @deprecated
  val udp_disable_domain_unmapping: Option[Boolean] = None

/**
 * Dial Fields
 *
 * ```json
 * {
 *   "detour": "upstream-out",
 *   "bind_interface": "en0",
 *   "inet4_bind_address": "0.0.0.0",
 *   "inet6_bind_address": "::",
 *   "routing_mark": 1234,
 *   "reuse_addr": false,
 *   "connect_timeout": "5s",
 *   "tcp_fast_open": false,
 *   "tcp_multi_path": false,
 *   "udp_fragment": false,
 *   "domain_strategy": "prefer_ipv6",
 *   "network_strategy": "default",
 *   "network_type": [],
 *   "fallback_network_type": [],
 *   "fallback_delay": "300ms"
 * }
 * ```
 *
 * -bind_interface -bind_address -routing_mark -reuse_addr -tcp_fast_open
 * -tcp_multi_path -udp_fragment -connect_timeout
 */
trait DialFieldsMixin:

  /** The tag of the upstream outbound. */
  val detour: Option[OutboundLike]

  /** The network interface to bind to. */
  val bind_interface: Option[String]

  /** The IPv4 address to bind to. */
  val inet4_bind_address: Option[Ipv4Address]

  /** The IPv6 address to bind to. */
  val inet6_bind_address: Option[Ipv6Address]

  /**
   * > [!NOTE] > Only supported on Linux.
   *
   * Set netfilter routing mark.
   */
  val routing_mark: Option[String]

  /** Reuse listener address. */
  val reuse_addr: Option[Boolean]

  /** Enable TCP Fast Open. */
  val tcp_fast_open: Option[Boolean]

  /** Enable TCP Multi Path. */
  val tcp_multi_path: Option[Boolean]

  /** Enable UDP fragmentation. */
  val udp_fragment: Option[Boolean]

  /**
   * Connect timeout, in golang's Duration format.
   *
   * A duration string is a possibly signed Seq of decimal numbers, each with optional
   * fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units
   * are "ns", "us" (or "µs"), "ms", "s", "m", "h".
   */
  val connect_timeout: Option[String]

  /**
   * One of prefer_ipv4 prefer_ipv6 ipv4_only ipv6_only.
   *
   * If set, the requested domain name will be resolved to IP before connect.
   *
   * | Outbound | Effected domains         | Fallback Value                          |
   * |:---------|:-------------------------|:----------------------------------------|
   * | direct   | Domain in request        | Take inbound.domain_strategy if not set |
   * | others   | Domain in server address | /                                       |
   */
  val domain_strategy: Option[DomainStrategy]

  /**
   * The length of time to wait before spawning a RFC 6555 Fast Fallback connection.
   * That is, is the amount of time to wait for connection to succeed before assuming
   * that IPv4/IPv6 is misconfigured and falling back to other type of addresses. If
   * zero, a default delay of `300ms` is used.
   *
   * Only take effect when [[domain_strategy]] is set.
   */
  val fallback_delay: Option[String]

  // def __attrs_post_init__(self):
  //     if self.detour and self.bind_interface:
  //         raise ValueError("'detour' and 'bind_interface' are mutually exclusive.")

/**
 * TCP Brutal Server Requirements
 *
 *   - Linux
 *   - `brutal` congestion control algorithm kernel module installed
 *
 * See [tcp-brutal](https://github.com/apernet/tcp-brutal) for details.
 *
 * ```json
 * {
 *   "enabled": true,
 *   "up_mbps": 100,
 *   "down_mbps": 100
 * }
 * ```
 */
case class TCPBrutal(
  /** Enable TCP Brutal congestion control algorithm */
  enabled: Boolean,
  /** Upload bandwidth in Mbps */
  up_mbps: Float,
  /** Download bandwidth in Mbps */
  down_mbps: Float,
)

/**
 * Inbound Multiplex
 *
 * ```json
 * {
 *   "enabled": true,
 *   "padding": false,
 *   "brutal": {}
 * }
 * ```
 */
case class InboundMultiplex(
  /**
   * Enable multiplex support.
   */
  enabled: Option[Boolean] = None,
  /**
   * If enabled, non-padded connections will be rejected.
   */
  padding: Option[Boolean] = None,
  brutal: Option[TCPBrutal] = None,
)

/**
 * Outbound Multiplex
 *
 * ```json
 * {
 *   "enabled": true,
 *   "protocol": "smux",
 *   "max_connections": 4,
 *   "min_streams": 4,
 *   "max_streams": 0,
 *   "padding": false,
 *   "brutal": {},
 * }
 * ```
 */
case class OutboundMultiplex(
  /** Enable multiplex. */
  val enabled: Option[Boolean] = None,
  /**
   * Multiplex protocol.
   *
   * | Protocol | Description                        |
   * |:---------|:-----------------------------------|
   * | smux     | https://github.com/xtaci/smux      |
   * | yamux    | https://github.com/hashicorp/yamux |
   * | h2mux    | https://golang.org/x/net/http2     |
   *
   * `h2mux` is used by default.
   */
  val protocol: Option["smux" | "yamux" | "h2mux"] = None,
  /** Max connections. Conflict with `max_streams`. */
  val max_connections: Option[Int] = None,
  /**
   * Minimum multiplexed streams in a connection before opening a new connection.
   *
   * Conflict with [[max_streams]].
   */
  val min_streams: Option[Int] = None,
  /**
   * Maximum multiplexed streams in a connection before opening a new connection.
   *
   * Conflict with [[max_connections]] and [[min_streams]].
   */
  val max_streams: Option[Int] = None,
  /** Enable padding for each stream. */
  val padding: Option[Boolean] = None,
  /** See [[TCPBrutal]] for details. */
  val brutal: Option[TCPBrutal] = None,
)
