package uniproxy.singbox.dns

import upickle.default.{Reader, ReadWriter, Writer}
import upickle.default.ReadWriter.{join, merge}

import uniproxy.typing.NetworkCIDR

import uniproxy.singbox.abc.AbstractSingBox
import uniproxy.singbox.{Inbound, Outbound}
import uniproxy.singbox.Outbound.outboundRW
import uniproxy.singbox.route.RuleSet
import uniproxy.singbox.typing.{DnsServerType, DomainStrategy, SniffProtocol}

/**
 * Ref: https://sing-box.sagernet.org/configuration/dns/
 *
 * @param servers List of [[DNS Servers]].
 * @param rules List of [[DNS Rules]].
 * @param final Default dns server tag. The first server will be used if empty.
 * @param strategy Default domain strategy for resolving the domain names. One
 *   of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. Take no effect
 *   if `server.strategy` is set.
 * @param disable_cache Disable dns cache.
 * @param disable_expire Disable dns cache expire.
 * @param independent_cache Make each DNS server's cache independent for special
 *   purposes. If enabled, will slightly degrade performance.
 * @param reverse_mapping Stores a reverse mapping of IP addresses after
 *   responding to a DNS query in order to provide domain names when routing.
 *
 * Since this process relies on the act of resolving domain names by an
 * application before making a request, it can be problematic in environments
 * such as macOS, where DNS is proxied and cached by the system.
 * @param fakeip FakeIP settings.
 * @param client_subnet Append a `edns0-subnet` OPT extra record with the
 *   specified IP address to every query by default. Can be overrides by
 *   `servers.[].client_subnet` or `rules.[].client_subnet`. @since v1.9.0
 */
case class DNS(
  servers: Option[Seq[DnsServer]] = None,
  rules: Option[Seq[DnsRule]] = None,
  `final`: Option[DnsServer] = None,
  strategy: Option[DomainStrategy] = None,
  disable_cache: Option[Boolean] = None,
  disable_expire: Option[Boolean] = None,
  independent_cache: Option[Boolean] = None,
  reverse_mapping: Option[Boolean] = None,
  fakeip: Option[FakeIP] = None,
  client_subnet: Option[String] = None,
) extends AbstractSingBox derives ReadWriter

enum DnsServer(tag: String, `type`: DnsServerType) derives ReadWriter {

  /** Deprecate since 1.11.0, remove in 1.13.0 */
  case LegacyDnsServer(
    tag: String,
    address: String, // | "local" | "dhcp://auto" | "fakeip",

    /**
     * Required if address contains domain
     *
     * Tag of another server to resolve the domain name in the address.
     */
    address_resolver: Option[DnsServer] = None,
    /**
     * The domain strategy for resolving the domain name in the address. One of
     * `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. `dns.strategy`
     * will be used if empty.
     */
    address_strategy: Option[DomainStrategy] = None,
    /**
     * Default domain strategy for resolving the domain names. One of
     * `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. Takes no effect
     * if overridden by other settings.
     */
    strategy: Option[DomainStrategy] = None,
    /**
     * Tag of an outbound for connecting to the DNS server.
     *
     * Default outbound will be used if empty.
     */
    detour: Option[Outbound] = None,
    client_subnet: Option[String] = None,
  ) extends DnsServer(tag, DnsServerType.legacy)

  /**
   * Ref: https://sing-box.sagernet.org/configuration/dns/server/local/
   *
   * ```json
   * {
   *   "type": "local",
   *   "tag": "",
   *   // Dial Fields
   * }
   * ```
   */
  case LocalDnsServer(
    tag: String,
    detour: Option[Outbound] = None,
  ) extends DnsServer(tag, DnsServerType.local)

  /**
   *    Ref: https://sing-box.sagernet.org/configuration/dns/server/udp/
   *
   *    ```json
   *    {
   *        "type": "udp",
   *        "tag": "",
   *
   *        "server": "",
   *        "server_port": 53,
   *
   * Dial Fields
   *    }
   */
  case UdpDnsServer(
    tag: String,
    server: String,
    server_port: Option[Int] = None,
    detour: Option[Outbound] = None,
  ) extends DnsServer(tag, DnsServerType.udp)

  /**
   * Ref: https://sing-box.sagernet.org/configuration/dns/server/https/
   *
   * ```json
   * {
   *     "type": "https",
   *     "tag": "",
   *
   *     "server": "",
   *     "server_port": 443,
   *
   *     "path": "",
   *     "headers": {},
   *
   *     "tls": {},
   *
   * Dial Fields
   * }
   * ```
   */
  case HttpsDnsServer(
    tag: String,
    server: String,
    server_port: Option[Int] = None,
    path: Option[String] = None,
    headers: Option[Map[String, String]] = None,
    tls: Option[Map[String, String]] = None,
    detour: Option[Outbound] = None,
    domain_resolver: Option[DnsServer] = None,
  ) extends DnsServer(tag, DnsServerType.https)

  /**
   * Ref: https://sing-box.sagernet.org/configuration/dns/server/http3/
   *
   * ```json
   * {
   *     "type": "h3",
   *     "tag": "",
   *
   *     "server": "",
   *     "server_port": 443,
   *
   *     "path": "",
   *     "headers": {},
   *
   *     "tls": {},
   *
   * Dial Fields
   * }
   * ```
   */
  case H3DnsServer(
    tag: String,
    server: String,
    server_port: Option[Int] = None,
    path: Option[String] = None,
    headers: Option[Map[String, String]] = None,
    tls: Option[Map[String, String]] = None,
    detour: Option[Outbound] = None,
    domain_resolver: Option[DnsServer] = None,
  ) extends DnsServer(tag, DnsServerType.h3)

  override def toString(): String = tag
}

given ipVersionReadWriter: ReadWriter[Option["4" | "6"]] =
  implicitly[ReadWriter[String]].bimap(
    opt => opt.map(_.toString()).getOrElse(""),
    strOpt =>
      if strOpt.isEmpty then None
      else
        Some(strOpt match {
          case "4" => "4"
          case "6" => "6"
        }),
  )
// given ipVersionWriter: Writer[Option["4" | "6"]] =
//   implicitly[Writer[String]].comap(opt => opt.map(_.toString()).getOrElse(""))
// given ipVersionReader: Reader[Option["4" | "6"]] = {
//   implicitly[Reader[String]].map {
//     case "4" => Some("4")
//     case "6" => Some("6")
//     case _   => None
//   }
// }
// given ipVersionReadWriter: ReadWriter[Option["4" | "6"]] = join(
//   ipVersionReader,
//   ipVersionWriter,
// )

case class DnsRule(
  server: DnsServer,
  outbound: Option[Outbound] = None,
  inbound: Option[Inbound] = None,
  ip_version: Option["4" | "6"] = None,
  auth_user: Option[String] = None,
  protocol: Option[SniffProtocol] = None,
  network: Option[String] = None,
  domain: Option[String] = None,
  domain_suffix: Option[String] = None,
  domain_keyword: Option[String] = None,
  domain_regex: Option[String] = None,
  ip_cidr: Option[Seq[NetworkCIDR]] = None,
  ip_is_private: Option[Boolean] = None,
  source_ip_cidr: Option[Seq[NetworkCIDR]] = None,
  source_ip_is_private: Option[Boolean] = None,
  source_port: Option[Int] = None,
  source_port_range: Option[Seq[String]] = None,
  port: Option[Seq[Int]] = None,
  port_range: Option[Seq[String]] = None,
  rule_set: Option[Seq[RuleSet] | RuleSet] = None,
  rule_set_ip_cidr_match_source: Option[Boolean] = None,
  rule_set_ip_cidr_accept_empty: Option[Boolean] = None,
  invert: Option[Boolean] = None,
) extends AbstractSingBox derives ReadWriter

/**
 * Ref: https://sing-box.sagernet.org/configuration/dns/fakeip/
 *
 * Example configuration:
 *
 * ```json
 * {
 *   "enabled": true,
 *   "inet4_range": "198.18.0.0/15",
 *   "inet6_range": "fc00::/18"
 * }
 * ```
 */
case class FakeIP(
  val enabled: Option[Boolean] = None,
  val inet4_range: Option[String] = None,
  val inet6_range: Option[String] = None,
) extends AbstractSingBox derives ReadWriter
