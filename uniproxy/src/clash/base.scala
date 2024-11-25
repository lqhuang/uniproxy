// base.scala

package uniproxy.clash.base

import scala.collection.immutable.Seq

import com.comcast.ip4s.{Host, Port}

import uniproxy.clash.typing.{
  ProtocolType,
  GroupType,
  RuleProviderType,
  RuleType
}

/** Abstract Clash class
  *
  * All Clash classes should inherit from this class.
  */
abstract trait AbstractClash {}

sealed trait ProtocolLike extends AbstractClash:
  val name: String

// Case classes for protocols and rules
class BaseProtocol(
    name: String,
    server: Host,
    port: Port,
    protocolType: ProtocolType
) extends ProtocolLike {
  override def toString: String = name
  def toMap: Map[String, String] = throw new NotImplementedError()
}

class BaseProxyProvider(
    name: String
) extends ProtocolLike {
  override def toString: String = name
}

class BaseProxyGroup(
    name: String,
    proxies: Seq[ProtocolLike | String],
    groupType: GroupType
) extends ProtocolLike {
  def proxiesOpts: String = proxies
    .map {
      case p: ProtocolLike => p.name
      case s: String       => s
    }
    .mkString(", ")

  def includeOtherGroup: Seq[BaseProxyGroup] = proxies.collect {
    case g: BaseProxyGroup => g
  }

  override def toString: String = name
}

sealed trait RuleProviderLike extends AbstractClash:
  val name: String

sealed trait BaseRule extends AbstractClash

class BaseRuleProvider(
    name: String,
    url: String,
    `type`: RuleProviderType
) extends RuleProviderLike {
  override def toString: String = name
}
