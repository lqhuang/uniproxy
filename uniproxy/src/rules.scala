package uniproxy
package rules

import uniproxy.typing.{BasicRuleType, GroupRuleType, RuleType}

import uniproxy.abc.{ProtocolLike, RuleProviderLike}

enum GroupRule(val `type`: GroupRuleType) {

  val matcher: Seq[RuleProviderLike]
  val policy: ProtocolLike

  case DomainGroupRule                              extends GroupRule("domain-group")
  case DomainSuffixGroupRule                        extends GroupRule("domain-suffix-group")
  case DomainKeywordGroupRule                       extends GroupRule("domain-keyword-group")
  case IPCidrGroupRule(noResolve: Option[Boolean])  extends GroupRule("ip-cidr-group")
  case IPCidr6GroupRule(noResolve: Option[Boolean]) extends GroupRule("ip-cidr6-group")
}

trait NoResolveable {
  val noResolve: Option[Boolean]
}

enum BasicRule(val `type`: RuleType) {
  val matcher: RuleProviderLike
  val policy: ProtocolLike

  case DomainRule        extends BasicRule("domain")
  case DomainSuffixRule  extends BasicRule("domain-suffix")
  case DomainKeywordRule extends BasicRule("domain-keyword")

  case IPCidrRule(val noResolve: Option[Boolean])  extends BasicRule("ip-cidr") with NoResolveable
  case IPCidr6Rule(val noResolve: Option[Boolean]) extends BasicRule("ip-cidr6") with NoResolveable
  case IPAsnRule(val noResolve: Option[Boolean])   extends BasicRule("ip-asn") with NoResolveable
  case GeoIPRule(val noResolve: Option[Boolean])   extends BasicRule("geoip") with NoResolveable

  case UserAgentRule   extends BasicRule("user-agent")
  case UrlRegexRule    extends BasicRule("url-regex")
  case ProcessNameRule extends BasicRule("process-name")

  case AndRule extends BasicRule("and")
  case OrRule  extends BasicRule("or")
  case NotRule extends BasicRule("not")

  case SubnetRule        extends BasicRule("subnet")
  case DestPortRule      extends BasicRule("dest-port")
  case SrcPortRule       extends BasicRule("src-port")
  case InPortRule        extends BasicRule("in-port")
  case SrcIPRule         extends BasicRule("src-ip")
  case ProtocolRule      extends BasicRule("protocol")
  case ScriptRule        extends BasicRule("script")
  case CellularRadioRule extends BasicRule("cellular-radio")
  case DeviceNameRule    extends BasicRule("device-name")

  case DomainSetRule extends BasicRule("domain-set")
  case RuleSetRule   extends BasicRule("rule-set")

  override def toString(): String = this match
      case r: NoResolveable =>
        r.noResolve match
            case Some(true) => s"${`type`.toUpperCase},${matcher},${policy},no-resolve"
            case _          => s"${`type`.toUpperCase},${matcher},${policy}"
      case _ =>
        s"${`type`.toUpperCase},${matcher},${policy}"
}

enum Rule(val `type`: RuleType) {
  import BasicRule.*
  import GroupRule.*

  case FinalRule(dnsFailed: Option[Boolean] = None) extends Rule("final")
}
