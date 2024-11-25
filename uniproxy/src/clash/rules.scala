package uniproxy.clash.rules

import uniproxy.clash.base.{ProtocolLike, RuleProviderLike}
import uniproxy.clash.typing.{RuleType}

class BasicRule(matcher: RuleProviderLike | String, policy: ProtocolLike) {
  val `type`: String

  def toString: String =
    s"${`type`.toUpperCase},${matcher},${policy}"
}

sealed trait ClashRule(val `type`: RuleType)

case class DomainRule(
    val matcher: RuleProviderLike | String,
    val policy: ProtocolLike
) extends BasicRule(matcher, policy)
    with ClashRule("domain")

case class DomainSuffixRule(
    val matcher: RuleProviderLike | String,
    val policy: ProtocolLike
) extends BasicRule(matcher, policy)
    with ClashRule("domain-suffix")

case class DomainKeywordRule() extends ClashRule("domain-keyword")

case class DomainSetRule() extends ClashRule("domain-set") {}

case class IPCidrRule(
    val no_resolve: Option[Boolean] = None
) extends ClashRule("ip-cidr") {

  def toString =
    no_resolve match
      case Some(true) =>
        f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
      case _ => f"{self.type.upper()},{self.matcher},{self.policy}"

}

case class IPCidr6Rule(
    no_resolve: Option[Boolean] = None
) extends ClashRule("ip-cidr6") {

  def toString =
    no_resolve match
      case Some(true) =>
        f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
      case _ => f"{self.type.upper()},{self.matcher},{self.policy}"

}

case class GeoIPRule(
    val no_resolve: Option[Boolean] = None
) extends ClashRule("geoip"):

  def toString =
    no_resolve match
      case Some(true) =>
        f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
      case _ => f"{self.type.upper()},{self.matcher},{self.policy}"

case class UserAgentRule(
) extends ClashRule("user-agent")

case class UrlRegexRule(
) extends ClashRule("url-regex")

case class ProcessNameRule(
) extends ClashRule("process-name")

case class AndRule() extends ClashRule("and")

case class OrRule() extends ClashRule("or")

case class NotRule() extends ClashRule("not")

case class SubnetRule() extends ClashRule("subnet")

case class DestPortRule() extends ClashRule("dest-port")

case class SrcPortRule() extends ClashRule("src-port")

case class InPortRule() extends ClashRule("in-port")

case class SrcIPRule() extends ClashRule("src-ip")

case class ProtocolRule() extends ClashRule("protocol")

case class ScriptRule() extends ClashRule("device-name")

case class RuleSetRule() extends ClashRule("rule-set")

case class FinalRule(
    policy: ProtocolLike | String,
    dnsFailed: Option[Boolean] = None
) extends ClashRule("final") {
  val `type` = "final"

  def toString: String = dnsFailed match {
    case Some(true) => s"${`type`.toUpperCase},${policy},dns-failed"
    case _          => s"${`type`.toUpperCase},${policy}"
  }
}

// def make_rules_from_uniproxy(
//     rule: UniproxyBasicRule | UniproxyGroupRule,
// ) -> tuple[ClashRule, ...]:
//     policy = to_name(rule.policy)

//     match rule:
//         case UniproxyBasicRule(matcher=matcher, type=typ):
//             if typ == "ip-asn":
//                 raise NotImplementedError(
//                     "`ip-asn` rule type not implemented yet for Clash"
//                 )
//             return (
//                 _CLASH_MAPPER[typ](
//                     matcher=to_name(matcher),
//                     policy=policy,
//                     type=typ,
//                 ),
//             )
//         case DomainGroupRule(matcher=matcher):
//             return tuple(
//                 DomainRule(matcher=str(each), policy=policy) for each in matcher
//             )
//         case DomainSuffixGroupRule(matcher=matcher):
//             return tuple(
//                 DomainSuffixRule(matcher=str(each), policy=policy) for each in matcher
//             )
//         case DomainKeywordGroupRule(matcher=matcher):
//             return tuple(
//                 DomainKeywordRule(matcher=str(each), policy=policy) for each in matcher
//             )
//         case IPCidrGroupRule(matcher=matcher, no_resolve=no_resolve):
//             return tuple(
//                 IPCidrRule(matcher=str(each), policy=policy, no_resolve=no_resolve)
//                 for each in matcher
//             )
//         case IPCidr6GroupRule(matcher=matcher, no_resolve=no_resolve):
//             return tuple(
//                 IPCidr6Rule(matcher=str(each), policy=policy, no_resolve=no_resolve)
//                 for each in matcher
//             )
//         case _:
//             raise ValueError("Invalid rule type")
