package uniproxy.singbox.dns

import uniproxy.typing.NetworkCIDR

import uniproxy.singbox.abc.{
  AbstractInbound,
  AbstractOutbound,
  AbstractSingBox,
  InboundLike,
  OutboundLike,
  RuleSetLike,
}

import uniproxy.singbox.typing.{DnsReturnCode, DomainStrategy, SniffProtocol}

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
  `final`: Option[String | DnsServer] = None,
  strategy: Option[DomainStrategy] = None,
  disable_cache: Option[Boolean] = None,
  disable_expire: Option[Boolean] = None,
  independent_cache: Option[Boolean] = None,
  reverse_mapping: Option[Boolean] = None,
  fakeip: Option[FakeIP] = None,
  client_subnet: Option[String] = None,
) extends AbstractSingBox

case class DnsServer(
  tag: String,
  address: String | DnsReturnCode | "local" | "dhcp://auto" | "fakeip",
  /**
   * Required if address contains domain
   *
   * Tag of another server to resolve the domain name in the address.
   */
  address_resolver: Option[String | DnsServer] = None,
  /**
   * The domain strategy for resolving the domain name in the address. One of
   * `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. `dns.strategy` will
   * be used if empty.
   */
  address_strategy: Option[DomainStrategy] = None,
  /**
   * Default domain strategy for resolving the domain names. One of
   * `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. Takes no effect if
   * overridden by other settings.
   */
  strategy: Option[DomainStrategy] = None,
  /**
   * Tag of an outbound for connecting to the DNS server.
   *
   * Default outbound will be used if empty.
   */
  detour: Option[OutboundLike] = None,
  client_subnet: Option[String] = None,
) extends AbstractSingBox

case class DnsRule(
  server: String | DnsServer,
  outbound: Option[OutboundLike | "any"] = None,
  inbound: Option[InboundLike] = None,
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
  rule_set: Option[Seq[RuleSetLike] | RuleSetLike] = None,
  rule_set_ip_cidr_match_source: Option[Boolean] = None,
  rule_set_ip_cidr_accept_empty: Option[Boolean] = None,
  invert: Option[Boolean] = None,
) extends AbstractSingBox

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
) extends AbstractSingBox
