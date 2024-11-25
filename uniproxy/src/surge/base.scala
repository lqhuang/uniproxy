// typing.scala

package uniproxy.surge.base

import uniproxy.surge.typing.{ProtocolType, GroupType}

import com.comcast.ip4s.{Host, Port}

/** Abstract Clash class
  *
  * All Surge classes should inherit from this class.
  */
abstract trait AbstractSurge {}

sealed trait ProtocolLike extends AbstractSurge {
  val name: String
}

class BaseProtocol(
    val name: String,
    val server: Host,
    val port: Port,
    val protocolType: ProtocolType
) extends AbstractSurge {
  override def toString: String = name
}

case class BaseProxyProvider(
    name: String
) extends AbstractSurge {
  override def toString: String = name
}

case class BaseProxyGroup(
    name: String,
    proxies: Seq[ProtocolLike | String],
    groupType: GroupType
) extends AbstractSurge {
  override def toString: String = name

  def proxiesOpts: String = {
    proxies
      .map {
        case s: String       => s
        case p: ProtocolLike => p.name
      }
      .mkString(", ")
  }

  def includeOtherGroups: Seq[BaseProxyGroup] = {
    proxies.collect { case Left(group: BaseProxyGroup) =>
      group
    }
  }

}
