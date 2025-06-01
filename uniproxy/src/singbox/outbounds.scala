package uniproxy.singbox

import com.comcast.ip4s.{Host, IpAddress, Ipv4Address, Ipv6Address, Port}
import upickle.default.{macroRW, ReadWriter}
import upickle.default.ReadWriter.merge

import uniproxy.typing.{ShadowsocksCipher, VmessCipher}
import uniproxy.singbox.abc.AbstractSingBox
import uniproxy.singbox.shared.{DialFieldsMixin, OutboundMultiplex}
import uniproxy.singbox.tls.OutboundTLS
import uniproxy.singbox.typing.{
  DomainStrategy,
  GroupOutboundType,
  OutboundType,
  ProtocolOutboundType,
  SingBoxNetwork,
}
import uniproxy.singbox.transports.Transport
import uniproxy.singbox.transports
import java.util.UUID

enum ProtocolOutbound(tag: String, `type`: ProtocolOutboundType)
    extends AbstractSingBox
       with DialFieldsMixin derives ReadWriter {

  /**
   * Examples:
   *
   * ```json
   * {
   * "type": "direct",
   * "tag": "direct-out",
   *
   * "override_address": "1.0.0.1",
   * "override_port": 53,
   * "proxy_protocol": 0,
   *
   * ... // Dial Fields
   * }
   * ```
   */
  case DirectOutbound(
    tag: String,
    /** Override the connection destination address. */
    override_address: Option[Host] = None,
    /** Override the connection destination port. */
    override_port: Option[Port] = None,
    /**
     * Write [Proxy
     * Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) in
     * the connection header. Protocol value can be `1` or `2`.
     */
    proxy_protocol: Option[1 | 2] = None,
    /** Dial Fields [[DialFieldsMixin]] */
    detour: Option[Outbound] = None,
    bind_interface: Option[String] = None,
    inet4_bind_address: Option[Ipv4Address] = None,
    inet6_bind_address: Option[Ipv6Address] = None,
    routing_mark: Option[String] = None,
    reuse_addr: Option[Boolean] = None,
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    connect_timeout: Option[String] = None,
    domain_strategy: Option[DomainStrategy] = None,
    fallback_delay: Option[String] = None,
  ) extends ProtocolOutbound(tag, ProtocolOutboundType.direct)

  /**
   * Shadowsocks Outbound
   *
   * Examples:
   *
   * ```json
   * {
   * "type": "shadowsocks",
   * "tag": "ss-out",
   *
   * "server": "127.0.0.1",
   * "server_port": 1080,
   * "method": "2022-blake3-aes-128-gcm",
   * "password": "8JCsPssfgS8tiRwiMlhARg==",
   * "plugin": "",
   * "plugin_opts": "",
   * "network": "udp",
   * "udp_over_tcp": false | {},
   * "multiplex": {},
   *
   * ... // Dial Fields
   * }
   * ```
   */
  case ShadowsocksOutbound(
    tag: String,
    /** The server address. */
    server: Host,
    /** The server port. */
    server_port: Port,
    /** Encryption methods. */
    method: ShadowsocksCipher,
    /** The shadowsocks password. */
    password: String,
    /** Shadowsocks SIP003 plugin, implemented in internal. */
    plugin: Option["obfs-local" | "v2ray-plugin"] = None,
    /** Shadowsocks SIP003 plugin options. */
    plugin_opts: Option[String] = None,
    /** Enabled network. One of `tcp`, `udp`. Both is enabled by default. */
    network: Option[SingBoxNetwork] = None,
    /** UDP over TCP configuration. Conflict with `multiplex. */
    udp_over_tcp: Option[Boolean] = None,
    /** See Multiplex for details. */
    multiplex: Option[OutboundMultiplex] = None,
    /** Dial Fields [[DialFieldsMixin]] */
    detour: Option[Outbound] = None,
    bind_interface: Option[String] = None,
    inet4_bind_address: Option[Ipv4Address] = None,
    inet6_bind_address: Option[Ipv6Address] = None,
    routing_mark: Option[String] = None,
    reuse_addr: Option[Boolean] = None,
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    connect_timeout: Option[String] = None,
    domain_strategy: Option[DomainStrategy] = None,
    fallback_delay: Option[String] = None,
  ) extends ProtocolOutbound(tag, ProtocolOutboundType.shadowsocks)

  case VmessOutbound(
    tag: String,
    server: Host,
    server_port: Port,
    uuid: UUID,
    security: VmessCipher,
    alter_id: Option[Int] = None,
    global_padding: Option[Boolean] = None,
    authenticated_length: Option[Boolean] = None,
    network: Option[SingBoxNetwork] = None,
    tls: Option[OutboundTLS] = None,
    packet_encoding: Option["packetaddr" | "xudp"] = None,
    transport: Option[Transport] = None,
    multiplex: Option[OutboundMultiplex] = None,
    /** Dial Fields [[DialFieldsMixin]] */
    detour: Option[Outbound] = None,
    bind_interface: Option[String] = None,
    inet4_bind_address: Option[Ipv4Address] = None,
    inet6_bind_address: Option[Ipv6Address] = None,
    routing_mark: Option[String] = None,
    reuse_addr: Option[Boolean] = None,
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    connect_timeout: Option[String] = None,
    domain_strategy: Option[DomainStrategy] = None,
    fallback_delay: Option[String] = None,
  ) extends ProtocolOutbound(tag, ProtocolOutboundType.vmess)

  /**
   * Trojan Outbound
   *
   * Examples:
   *
   * ```json
   * {
   *   "type": "trojan",
   *   "tag": "trojan-out",
   *
   *   "server": "127.0.0.1",
   *   "server_port": 1080,
   *   "password": "8JCsPssfgS8tiRwiMlhARg==",
   *   "network": "tcp",
   *   "tls": {},
   *   "multiplex": {},
   *   "transport": {},
   *
   *   ... // Dial Fields
   * }
   * ```
   */
  case TrojanOutbound(
    tag: String,
    server: Host,
    /** The server address. */
    server_port: Port,
    /** The server port. */
    password: String,
    /** The Trojan password. */
    tls: Option[OutboundTLS] = None,
    /** TLS configuration, see [[TLS]]. */
    multiplex: Option[OutboundMultiplex] = None,
    /** See [[Multiplex]] for details. */
    transport: Option[Transport] = None,
    /** V2Ray Transport configuration, see V2Ray Transport. */
    /** Dial Fields [[DialFieldsMixin]] */
    detour: Option[Outbound] = None,
    bind_interface: Option[String] = None,
    inet4_bind_address: Option[Ipv4Address] = None,
    inet6_bind_address: Option[Ipv6Address] = None,
    routing_mark: Option[String] = None,
    reuse_addr: Option[Boolean] = None,
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    connect_timeout: Option[String] = None,
    domain_strategy: Option[DomainStrategy] = None,
    fallback_delay: Option[String] = None,
  ) extends ProtocolOutbound(tag, ProtocolOutboundType.trojan)

}

enum GroupOutbound(`type`: GroupOutboundType) derives ReadWriter {

  /**
   * SelectorOutbound
   *
   * Examples:
   *
   * ```json
   * {
   *     "type": "selector",
   *     "tag": "select",
   *
   *     "outbounds": [
   *         "proxy-a",
   *         "proxy-b",
   *         "proxy-c"
   *     ],
   *     "default": "proxy-c",
   *     "interrupt_exist_connections": false
   * }
   * ```
   */
  case SelectorOutbound(
    tag: String,
    outbounds: Seq[Outbound],
    default: Option[Outbound] = None,
    interrupt_exist_connections: Option[Boolean] = None,
  ) extends GroupOutbound(GroupOutboundType.selector)

  /**
   * UrlTestOutbound
   *
   * Examples:
   *
   * ```json
   * {
   *   "type": "urltest",
   *   "tag": "auto",
   *
   *   "outbounds": [
   *     "proxy-a",
   *     "proxy-b",
   *     "proxy-c"
   *   ],
   *   "url": "",
   *   "interval": "",
   *   "tolerance": 0,
   *   "idle_timeout": "",
   *   "interrupt_exist_connections": false
   * }
   * ```
   */
  case UrlTestOutbound(
    tag: String,
    /** List of outbound tags to test. */
    outbounds: Seq[Outbound],
    /**
     * The URL to test. `https://www.gstatic.com/generate_204` will be used if
     * empty.
     */
    url: Option[String] = None,
    /** The test interval. `3m` will be used if empty. */
    interval: Option[String] = None,
    /** The test tolerance in milliseconds. `50` will be used if empty. */
    tolerance: Option[Float] = None,
    /** The idle timeout. 30m will be used if empty. */
    idle_timeout: Option[String] = None,

    /**
     * Interrupt existing connections when the selected outbound has changed.
     *
     * Only outbound connections are affected by this setting, internal
     * connections will always be interrupted.
     */
    interrupt_exist_connections: Option[Boolean] = None,
  ) extends GroupOutbound(GroupOutboundType.urltest)

}

type Outbound = ProtocolOutbound | GroupOutbound
object Outbound {
  export ProtocolOutbound.*
  export GroupOutbound.*

  given outboundRW: ReadWriter[Outbound] = merge(
    ProtocolOutbound.derived$ReadWriter,
    GroupOutbound.derived$ReadWriter,
  )
}
