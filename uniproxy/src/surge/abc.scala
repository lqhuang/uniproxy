package uniproxy.surge.abc

import uniproxy.surge.typing.{GroupType, ProtocolType}

import com.comcast.ip4s.{Host, Port}

/**
 * Abstract Clash class
 *
 * All Surge classes should inherit from this class.
 */
abstract trait AbstractSurge

abstract class AbstractProtocol extends AbstractSurge:
  val name: String
  val server: Host
  val port: Port
  val protocolType: ProtocolType

abstract class AbstractProxyProvider(name: String) extends AbstractSurge

abstract class AbstractProxyGroup extends AbstractSurge {
  val name: String
  val proxies: Seq[ProtocolLike | String]
  val groupType: GroupType

  override def toString: String = name

  def proxiesOpts: String = {
    proxies
      .map { p =>
        p match
          case s: String => s
          case _         => s"${p}"
      }
      .mkString(", ")
  }

  // def includeOtherGroups: Seq[AbstractProxyGroup] = {
  //   proxies.collect { case Left(group: AbstractProxyGroup) =>
  //     group
  //   }
  // }

}

abstract class AbstractRuleProvider(name: String) extends AbstractSurge

type ProtocolLike = AbstractProtocol | AbstractProxyGroup | String
type ProxyProviderLike = AbstractProxyProvider | String
type RuleProviderLike = AbstractRuleProvider | String
