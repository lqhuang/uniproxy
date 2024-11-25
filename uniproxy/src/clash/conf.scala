import com.comcast.ip4s.{Host, Port, SocketAddress}
import com.comcast.ip4s.IpAddress

// Type aliases using literal types
type Mode = "rule" | "global" | "direct"
type LogLevelType = "silent" | "info" | "warning" | "error" | "debug"

// Collection type aliases
type Hosts = Map[String, String]
type Proxies = Seq[BaseProtocol]
type ProxyProviders = Seq[BaseProxyProvider]
type ProxyGroups = Seq[BaseProxyGroup]
type RuleProviders = Seq[RuleProvider]
type Rules = Seq[BaseRule]

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
    rules: Rules = Seq.empty
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
