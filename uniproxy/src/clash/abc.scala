package uniproxy
package clash
package abc

import com.comcast.ip4s.{Host, Port}

import uniproxy.typing.{GroupType, Network, ProtocolType}

/**
 * Abstract classes for clash
 *
 * All clash classes should inherit from this class.
 */
abstract class AbstractClash

abstract class AbstractProtocol extends AbstractClash:
  val name: String
  val server: Host
  val port: Port
  val `type`: ProtocolType

abstract class AbstractProxyGroup extends AbstractClash:
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

abstract class AbstractProxyProvider extends AbstractClash:
  val name: String
  val `type`: GroupType
  val url: String
  val path: Option[String]

abstract class AbstractRule extends AbstractClash

abstract class AbstractRuleProvider extends AbstractClash:
  val name: String
  val url: String
  val path: Option[String]
  val interval: Option[Float]

type ProtocolLike = AbstractProtocol | AbstractProxyGroup | String
type ProxyProviderLike = AbstractProxyProvider | String
type ProxyGroupLike = AbstractProxyGroup | String

type RuleProviderLike = AbstractRuleProvider | String
