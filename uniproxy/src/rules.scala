// scalafmt: { maxColumn = 180, align.preset = more }
package uniproxy
package rules

import uniproxy.typing.{BasicRuleType, GroupRuleType, RuleType}
import uniproxy.abc.{AbstractRule, ProtocolLike, RuleProviderLike}

type Matcher = RuleProviderLike
type Policy  = ProtocolLike

sealed trait Matchable

sealed trait BasicMatchable extends Matchable:
  val matcher: Matcher
  val policy: Policy
sealed trait BasicResolvedMatchable extends Matchable:
  val matcher: Matcher
  val policy: Policy
  val noResolve: Boolean
sealed trait GroupMatchable extends Matchable:
  val matchers: Seq[Matcher]
  val policy: Policy
sealed trait GroupResolvedMatchable extends Matchable:
  val matchers: Seq[Matcher]
  val policy: Policy
  val noResolve: Boolean

enum BasicRule(`type`: BasicRuleType) extends AbstractRule {

  case DomainRule(matcher: Matcher, policy: Policy)        extends BasicRule(BasicRuleType.domain) with BasicMatchable
  case DomainSuffixRule(matcher: Matcher, policy: Policy)  extends BasicRule(BasicRuleType.`domain-suffix`) with BasicMatchable
  case DomainKeywordRule(matcher: Matcher, policy: Policy) extends BasicRule(BasicRuleType.`domain-keyword`) with BasicMatchable

  case IPCidrRule(matcher: Matcher, policy: Policy, noResolve: Boolean = true)  extends BasicRule(BasicRuleType.`ip-cidr`) with BasicResolvedMatchable
  case IPCidr6Rule(matcher: Matcher, policy: Policy, noResolve: Boolean = true) extends BasicRule(BasicRuleType.`ip-cidr6`) with BasicResolvedMatchable
  case IPAsnRule(matcher: Matcher, policy: Policy, noResolve: Boolean = true)   extends BasicRule(BasicRuleType.`ip-asn`) with BasicResolvedMatchable
  case GeoIPRule(matcher: Matcher, policy: Policy, noResolve: Boolean = true)   extends BasicRule(BasicRuleType.`geoip`) with BasicResolvedMatchable

  case UserAgentRule(matcher: Matcher, policy: Policy)   extends BasicRule(BasicRuleType.`user-agent`) with BasicMatchable
  case UrlRegexRule(matcher: Matcher, policy: Policy)    extends BasicRule(BasicRuleType.`url-regex`) with BasicMatchable
  case ProcessNameRule(matcher: Matcher, policy: Policy) extends BasicRule(BasicRuleType.`process-name`) with BasicMatchable

  case AndRule(matcher: Matcher, policy: Policy) extends BasicRule(BasicRuleType.and) with BasicMatchable
  case OrRule(matcher: Matcher, policy: Policy)  extends BasicRule(BasicRuleType.or) with BasicMatchable
  case NotRule(matcher: Matcher, policy: Policy) extends BasicRule(BasicRuleType.not) with BasicMatchable

  case SubnetRule(matcher: Matcher, policy: Policy)        extends BasicRule(BasicRuleType.subnet) with BasicMatchable
  case DestPortRule(matcher: Matcher, policy: Policy)      extends BasicRule(BasicRuleType.`dest-port`) with BasicMatchable
  case SrcPortRule(matcher: Matcher, policy: Policy)       extends BasicRule(BasicRuleType.`src-port`) with BasicMatchable
  case InPortRule(matcher: Matcher, policy: Policy)        extends BasicRule(BasicRuleType.`in-port`) with BasicMatchable
  case SrcIPRule(matcher: Matcher, policy: Policy)         extends BasicRule(BasicRuleType.`src-ip`) with BasicMatchable
  case ProtocolRule(matcher: Matcher, policy: Policy)      extends BasicRule(BasicRuleType.protocol) with BasicMatchable
  case ScriptRule(matcher: Matcher, policy: Policy)        extends BasicRule(BasicRuleType.script) with BasicMatchable
  case CellularRadioRule(matcher: Matcher, policy: Policy) extends BasicRule(BasicRuleType.`cellular-radio`) with BasicMatchable
  case DeviceNameRule(matcher: Matcher, policy: Policy)    extends BasicRule(BasicRuleType.`device-name`) with BasicMatchable

  case DomainSetRule(matcher: Matcher, policy: Policy) extends BasicRule(BasicRuleType.`domain-set`) with BasicMatchable
  case RuleSetRule(matcher: Matcher, policy: Policy)   extends BasicRule(BasicRuleType.`rule-set`) with BasicMatchable

  case FinalRule(policy: Policy, dnsFailed: Boolean = true) extends BasicRule(BasicRuleType.`final`)

  override def toString(): String = this match
    case r: BasicResolvedMatchable if r.noResolve      => s"${`type`.toString.toUpperCase},${r.matcher},${r.policy},no-resolve"
    case r: BasicResolvedMatchable if !r.noResolve     => s"${`type`.toString.toUpperCase},${r.matcher},${r.policy}"
    case r: BasicMatchable                             => s"${`type`.toString.toUpperCase},${r.matcher},${r.policy}"
    case uniproxy.rules.BasicRule.IPCidrRule(_, _, _)  => ???
    case uniproxy.rules.BasicRule.IPCidr6Rule(_, _, _) => ???
    case uniproxy.rules.BasicRule.IPAsnRule(_, _, _)   => ???
    case uniproxy.rules.BasicRule.GeoIPRule(_, _, _)   => ???
    case FinalRule(policy, dnsFailed)                  => s"${`type`.toString.toUpperCase},${policy}" ++ (if dnsFailed then ",dns-failed" else "")
}

enum GroupRule(`type`: GroupRuleType) extends AbstractRule {

  def toBasicRules(): Seq[BasicRule] = this match
    case DomainGroupRule(matchers, policy)             => matchers.map(DomainRule(_, policy))
    case DomainSuffixGroupRule(matchers, policy)       => matchers.map(DomainSuffixRule(_, policy))
    case DomainKeywordGroupRule(matchers, policy)      => matchers.map(DomainKeywordRule(_, policy))
    case IPCidrGroupRule(matchers, policy, noResolve)  => matchers.map(IPCidrRule(_, policy, noResolve))
    case IPCidr6GroupRule(matchers, policy, noResolve) => matchers.map(IPCidr6Rule(_, policy, noResolve))

  case DomainGroupRule(matchers: Seq[Matcher], policy: Policy)        extends GroupRule(GroupRuleType.`domain-group`) with GroupMatchable
  case DomainSuffixGroupRule(matchers: Seq[Matcher], policy: Policy)  extends GroupRule(GroupRuleType.`domain-suffix-group`) with GroupMatchable
  case DomainKeywordGroupRule(matchers: Seq[Matcher], policy: Policy) extends GroupRule(GroupRuleType.`domain-keyword-group`) with GroupMatchable

  case IPCidrGroupRule(matchers: Seq[Matcher], policy: Policy, noResolve: Boolean = true)  extends GroupRule(GroupRuleType.`ip-cidr-group`) with GroupResolvedMatchable
  case IPCidr6GroupRule(matchers: Seq[Matcher], policy: Policy, noResolve: Boolean = true) extends GroupRule(GroupRuleType.`ip-cidr6-group`) with GroupResolvedMatchable
}

type Rule = BasicRule | GroupRule

extension (rule: Rule)
  def `type`: RuleType = rule match
    case r: BasicRule => r.`type`
    case r: GroupRule => r.`type`

export BasicRule.*
export GroupRule.*
