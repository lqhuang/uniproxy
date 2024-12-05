// scalafmt: { maxColumn = 150, align.preset = more }
package uniproxy
package surge
package rules

import uniproxy.surge.abc.{ProtocolLike, RuleProviderLike}

import uniproxy.surge.typing.RuleType

sealed trait MatchableRule {
  val matcher: Matcher
  val policy: Policy
}
trait BasicRule extends MatchableRule
trait NoResolveBasicRule extends MatchableRule {
  val noResolve: Boolean
}

type Matcher = RuleProviderLike
type Policy  = ProtocolLike

enum Rule(`type`: RuleType) {

  override def toString(): String = this match
    case r: FinalRule =>
      s"${`type`.toUpperCase},${r.policy},${r.dnsFailed}"
    case r: NoResolveBasicRule if r.noResolve =>
      s"${`type`.toUpperCase},${r.matcher},${r.policy},no-resolve"
    case r: NoResolveBasicRule if !r.noResolve =>
      s"${`type`.toUpperCase},${r.matcher},${r.policy}"
    case r: MatchableRule =>
      s"${`type`.toUpperCase},${r.matcher},${r.policy}"

  case DomainRule(matcher: Matcher, policy: Policy)        extends Rule("domain") with BasicRule
  case DomainSuffixRule(matcher: Matcher, policy: Policy)  extends Rule("domain-suffix") with BasicRule
  case DomainKeywordRule(matcher: Matcher, policy: Policy) extends Rule("domain-keyword") with BasicRule

  case IPCidrRule(matcher: Matcher, policy: Policy, noResolve: Boolean)  extends Rule("ip-cidr") with NoResolveBasicRule
  case IPCidr6Rule(matcher: Matcher, policy: Policy, noResolve: Boolean) extends Rule("ip-cidr6") with NoResolveBasicRule
  case IPAsnRule(matcher: Matcher, policy: Policy, noResolve: Boolean)   extends Rule("ip-asn") with NoResolveBasicRule
  case GeoIPRule(matcher: Matcher, policy: Policy, noResolve: Boolean)   extends Rule("geoip") with NoResolveBasicRule

  case UserAgentRule(matcher: Matcher, policy: Policy)   extends Rule("user-agent") with BasicRule
  case UrlRegexRule(matcher: Matcher, policy: Policy)    extends Rule("url-regex") with BasicRule
  case ProcessNameRule(matcher: Matcher, policy: Policy) extends Rule("process-name") with BasicRule

  case AndRule(matcher: Matcher, policy: Policy) extends Rule("and") with BasicRule
  case OrRule(matcher: Matcher, policy: Policy)  extends Rule("or") with BasicRule
  case NotRule(matcher: Matcher, policy: Policy) extends Rule("not") with BasicRule

  case SubnetRule(matcher: Matcher, policy: Policy)        extends Rule("subnet") with BasicRule
  case DestPortRule(matcher: Matcher, policy: Policy)      extends Rule("dest-port") with BasicRule
  case SrcPortRule(matcher: Matcher, policy: Policy)       extends Rule("src-port") with BasicRule
  case InPortRule(matcher: Matcher, policy: Policy)        extends Rule("in-port") with BasicRule
  case SrcIPRule(matcher: Matcher, policy: Policy)         extends Rule("src-ip") with BasicRule
  case ProtocolRule(matcher: Matcher, policy: Policy)      extends Rule("protocol") with BasicRule
  case ScriptRule(matcher: Matcher, policy: Policy)        extends Rule("script") with BasicRule
  case CellularRadioRule(matcher: Matcher, policy: Policy) extends Rule("cellular-radio") with BasicRule
  case DeviceNameRule(matcher: Matcher, policy: Policy)    extends Rule("device-name") with BasicRule

  case DomainSetRule(matcher: Matcher, policy: Policy) extends Rule("domain-set") with BasicRule
  case RuleSetRule(matcher: Matcher, policy: Policy)   extends Rule("rule-set") with BasicRule

  case FinalRule(policy: Policy, dnsFailed: Boolean = false) extends Rule("final")
}

export Rule.*
