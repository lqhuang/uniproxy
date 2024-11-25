package uniproxy.abc

import com.comcast.ip4s.{Host, Port}

import uniproxy.typing.{GroupType, ProtocolType, Network}

/** Abstract classes for uniproxy
  *
  * All uniproxy classes should inherit from this class.
  */
abstract trait AbstractUniproxy {}

abstract class AbstractProtocol extends AbstractUniproxy:
  val name: String
  val `type`: ProtocolType
  val server: Host
  val port: Port

  def toString() = name

abstract class AbstractProxyGroup extends AbstractUniproxy:
  val name: String
  val `type`: GroupType
  val proxies: Option[Seq[ProtocolLike]] = None
  val providers: Option[Seq[ProxyProviderLike]] = None
  val network: Option[Network] = Some("tcp_and_udp")

  val url: String = "https://www.gstatic.com/generate_204"
  val interval: Float = 300
  val timeout: Float = 3

  // TODO: update to `HealthCheck` class
  val health_check: Option[Boolean] = None

  def toString(): String = name

abstract class AbstractProxyProvider extends AbstractUniproxy:
  val name: String
  val `type`: GroupType
  val url: String
  val path: Option[String]

  def toString(): String = name

abstract class AbstractRule extends AbstractUniproxy:
  val name: String
  val `type`: String

abstract class AbstractRuleProvider extends AbstractUniproxy:
  val name: String
  val url: String
  val path: Option[String]
  val interval: Option[Float]

type ProtocolLike = AbstractProtocol | AbstractProxyGroup | String
type ProxyProviderLike = AbstractProxyProvider | String
type RuleProviderLike = AbstractRuleProvider | String
