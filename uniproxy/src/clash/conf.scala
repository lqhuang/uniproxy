package uniproxy
package clash
package conf

import com.comcast.ip4s.{Host, Port, SocketAddress}
import com.comcast.ip4s.IpAddress

import uniproxy.typing.{GroupType, Network, ProtocolType}
import uniproxy.clash.abc.{
  AbstractClash,
  ProtocolLike,
  ProxyGroupLike,
  ProxyProviderLike,
  RuleProviderLike,
}
import uniproxy.clash.rules.Rule

// Type aliases using literal types
type Mode = "rule" | "global" | "direct"
type LogLevelType = "silent" | "info" | "warning" | "error" | "debug"

// Collection type aliases
type Hosts = Map[String, String]
type Proxies = Seq[ProtocolLike]
type ProxyProviders = Seq[ProxyProviderLike]
type ProxyGroups = Seq[ProxyGroupLike]
type RuleProviders = Seq[RuleProviderLike]
type Rules = Seq[Rule]

// Main configuration case class
case class ClashConfig(
  mode: Mode,
  logLevel: LogLevelType,
  ipv6: Boolean,

  // Network settings
  port: Port,
  socksPort: Int,
  redirPort: Int,
  mixedPort: Int,
  allowLan: Boolean,
  bindAddress: String,

  // External controller settings
  externalController: SocketAddress[IpAddress],
  externalUI: String,
  externalUiUrl: String,
  secret: String,

  // proxy
  proxies: Proxies = Seq.empty,
  proxyProviders: ProxyProviders = Seq.empty,
  proxyGroups: ProxyGroups = Seq.empty,

  // rules
  ruleProviders: RuleProviders = Seq.empty,
  rules: Rules = Seq.empty,
) extends AbstractClash

// // Helper constants if needed
// object ClashConfig {
//   val Modes = Map(
//     "Rule" -> "rule",
//     "Global" -> "global",
//     "Direct" -> "direct"
//   )

//   val LogLevels = Map(
//     "Silent" -> "silent",
//     "Info" -> "info",
//     "Warning" -> "warning",
//     "Error" -> "error",
//     "Debug" -> "debug"
//   )
// }
