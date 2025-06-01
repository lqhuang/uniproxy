package uniproxy.singbox.route

import upickle.default.ReadWriter

import uniproxy.singbox.abc.{AbstractRuleSet, AbstractSingBox, InboundLike, OutboundLike}
import uniproxy.singbox.typing.{RuleSetFormat, RuleSetType, SingBoxNetwork, SniffProtocol}

enum RuleSet(tag: String, format: RuleSetFormat, `type`: RuleSetType) extends ReadWriter {
  case LocalRuleSet(tag: String, format: RuleSetFormat, path: String)
      extends RuleSet(tag, format, RuleSetType.local)

  case RemoteRuleSet(
    tag: String,
    format: RuleSetFormat,
    url: String,
    download_detour: Option[InboundLike] = None,
    update_interval: Option[Float] = None,
  ) extends RuleSet(tag, format, RuleSetType.remote)
}

case class Rule(
  outbound: OutboundLike,
  inbound: Option[Seq[OutboundLike] | Seq[String]] = None,
  ip_version: Option["4" | "6"] = None,
  auth_user: Option[String | Seq[String]] = None,
  protocol: Option[SniffProtocol] = None,
  network: Option[SingBoxNetwork] = None,
  domain: Option[String | Seq[String]] = None,
  domain_suffix: Option[String | Seq[String]] = None,
  domain_keyword: Option[String | Seq[String]] = None,
  domain_regex: Option[String | Seq[String]] = None,
  ip_cidr: Option[String | Seq[String]] = None,
  ip_is_private: Option[Boolean] = None,
  source_ip_cidr: Option[Seq[String]] = None,
  source_ip_is_private: Option[Boolean] = None,
  source_port: Option[Int | Seq[Int]] = None,
  source_port_range: Option[String | Seq[String]] = None,
  port: Option[Int | Seq[Int]] = None,
  port_range: Option[String | Seq[String]] = None,
  rule_set: Option[RuleSet | Seq[RuleSet]] = None,
  rule_set_ip_cidr_match_source: Option[Boolean] = None,
  invert: Option[Boolean] = None,
) extends ReadWriter

// def from_uniproxy(cls, rule: UniproxyBasicRule | UniproxyGroupRule) -> Rule:
//     if not isinstance(rule, (UniproxyBasicRule, UniproxyGroupRule)):
//         raise ValueError(f"Expected UniproxyBasicRule, got {type(rule)}")

//     rule match :
//         case (
//             DomainRule(matcher=matcher, policy=policy)
//             | DomainGroupRule(matcher=matcher, policy=policy)
//         ):
//             return cls(outbound=String(policy), domain=matcher)  # type: ignore[reportArgumentType, arg-type]
//         case (
//             DomainSuffixRule(matcher=matcher, policy=policy)
//             | DomainSuffixGroupRule(matcher=matcher, policy=policy)
//         ):
//             return cls(outbound=String(policy), domain_suffix=matcher)  # type: ignore[reportArgumentType, arg-type]
//         case (
//             DomainKeywordRule(matcher=matcher, policy=policy)
//             | DomainKeywordGroupRule(matcher=matcher, policy=policy)
//         ):
//             return cls(outbound=String(policy), domain_keyword=matcher)  # type: ignore[reportArgumentType, arg-type]
//         case (
//             IPCidrRule(matcher=matcher, policy=policy)
//             | IPCidrGroupRule(matcher=matcher, policy=policy)
//             | IPCidr6Rule(matcher=matcher, policy=policy)
//             | IPCidr6GroupRule(matcher=matcher, policy=policy)
//         ):
//             return cls(outbound=String(policy), ip_cidr=matcher)  # type: ignore[reportArgumentType, arg-type]
//         case GeoIPRule(matcher=matcher, policy=policy):
//             # TODO: add extra opts to give a prefix or suffix
//             return cls(outbound=String(policy), rule_set=f"rs-geoip-{matcher}".lower())
//         case (
//             RuleSetRule(matcher, policy)
//             | DomainSetRule(matcher=matcher, policy=policy)
//         ):
//             matcher = String(matcher)
//             if matcher.startswith("http") and "://" in matcher:
//                 raise ValueError(
//                     f"Direct URL ({matcher}) is not supported currently while transforming from uniproxy external rule to sing-box rule"
//                 )
//             return cls(outbound=String(policy), rule_set=matcher)
//         case _:
//             raise ValueError(f"Unsupported rule type yet: {type(rule)}")

case class Route(
  /** List of route [[Rule]] */
  val rules: Seq[Rule],
  /** List of [[RuleSet]] */
  val rule_set: Option[Seq[RuleSet]] = None,
  /** Default outbound tag. the first outbound will be used if empty. */
  val `final`: Option[OutboundLike] = None,
  /**
   * > [!WARN] Only supported on Linux, Windows and macOS.
   *
   * Bind outbound connections to the default NIC by default to prevent routing
   * loops under tun.
   *
   * Takes no effect if `outbound.bind_interface` is set.
   */
  val auto_detect_interface: Option[Boolean] = None,
  /**
   * > [!WARN] Only supported on Android.
   *
   * Accept Android VPN as upstream NIC when `auto_detect_interface` enabled.
   */
  val override_android_vpn: Option[Boolean] = None,
  /**
   * > [!WARN] Only supported on Linux, Windows and macOS.
   *
   * Bind outbound connections to the specified NIC by default to prevent
   * routing loops under tun.
   *
   * Takes no effect if `auto_detect_interface` is set.
   */
  val default_interface: Option[String] = None,
  /**
   * > [!WARN] Only supported on Linux.
   *
   * Set routing mark by default.
   *
   * Takes no effect if `outbound.routing_mark` is set.
   */
  val default_mark: Option[Int] = None,
) extends AbstractSingBox derives ReadWriter
