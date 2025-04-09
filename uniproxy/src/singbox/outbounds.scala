package uniproxy.singbox.outbounds

import com.comcast.ip4s.{Host, Ipv4Address, Ipv6Address, Port}
import com.comcast.ip4s.IpAddress

import uniproxy.typing.{ShadowsocksCipher, VmessCipher}

import uniproxy.singbox.abc.{AbstractOutbound, OutboundLike}
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

case class WireGuardPeer(
  /** WireGuard allowed IPs */
  allowed_ips: Seq[IpAddress],
  /** The server address. Required if multi-peer disabled */
  server: Option[Host] = None,
  /** The server port. Required if multi-peer disabled */
  server_port: Option[Int] = None,
  /**
   * Required if multi-peer disabled
   *
   * WireGuard peer public key.
   */
  peer_public_key: Option[String] = None,
  /** WireGuard pre-shared key */
  pre_shared_key: Option[String] = None,
  /**
   * WireGuard reserved field bytes.
   *
   * `$outbound.reserved` will be used if empty.
   */
  reserved: Option[Seq[Int]] = None,
)

enum ProtocolOutbound(`type`: ProtocolOutboundType) extends AbstractOutbound {

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
    detour: Option[OutboundLike] = None,
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
  ) extends ProtocolOutbound("direct") with DialFieldsMixin

  /**
   * Examples:
   *
   * ```json
   * {
   * "type": "block",
   * "tag": "block"
   * }
   * ```
   */
  case BlockOutbound(tag: String) extends ProtocolOutbound("block")

  /**
   * Examples:
   *
   * ```json
   * {
   * "type": "dns",
   * "tag": "dns-out"
   * ...
   * ```
   */
  case DnsOutbound(tag: String) extends ProtocolOutbound("dns")

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
    detour: Option[OutboundLike] = None,
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
  ) extends ProtocolOutbound("shadowsocks") with DialFieldsMixin

  case VmessOutbound(
    tag: String,
    server: Host,
    server_port: Port,
    uuid: String,
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
    detour: Option[OutboundLike] = None,
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
  ) extends ProtocolOutbound("vmess") with DialFieldsMixin

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
    detour: Option[OutboundLike] = None,
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
  ) extends ProtocolOutbound("trojan") with DialFieldsMixin

  /**
   * Examples:
   *
   * ```json
   * {
   * "type": "wireguard",
   * "tag": "wireguard-out",
   *
   * "server": "127.0.0.1",
   * "server_port": 1080,
   * "system_interface": false,
   * "gso": false,
   * "interface_name": "wg0",
   * "local_address": [
   *     "10.0.0.2/32"
   * ],
   * "private_key": "YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04=",
   * "peers": [
   *     {
   *     "server": "127.0.0.1",
   *     "server_port": 1080,
   *     "public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=",
   *     "pre_shared_key": "31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM=",
   *     "allowed_ips": [
   *         "0.0.0.0/0"
   *     ],
   *     "reserved": [0, 0, 0]
   *     }
   * ],
   * "peer_public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=",
   * "pre_shared_key": "31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM=",
   * "reserved": [0, 0, 0],
   * "workers": 4,
   * "mtu": 1408,
   * "network": "tcp",
   *
   * ... // Dial Fields
   * }
   * ```
   */
  case WireguardOutbound(
    tag: String,
    /**
     * Required**
     *
     * List of IP (v4 or v6) address prefixes to be assigned to the interface.
     */
    local_address: Seq[Host],
    /**
     * Required**
     *
     * WireGuard requires base64-encoded public and private keys. These can be
     * generated using the wg(8) utility:
     *
     * ```
     * wg genkey
     * echo "private key" || wg pubkey
     * ```
     */
    private_key: String,
    /** The server address. Required if multi-peer disabled. */
    server: Option[Host] = None,
    /** The server port. Required if multi-peer disabled. */
    server_port: Option[Port] = None,
    /** Required if multi-peer disabled. WireGuard peer public key. */
    peer_public_key: Option[String] = None,
    /** WireGuard pre-shared key. */
    pre_shared_key: Option[String] = None,
    /**
     * Multi-peer support.
     *
     * If enabled, `server`, `server_port`, `peer_public_key`, `pre_shared_key`
     * will be ignored.
     */
    peers: Option[Seq[WireGuardPeer]] = None,
    /** WireGuard reserved field bytes. */
    reserved: Option[Seq[Int]] = None,
    /**
     * Use system interface.
     *
     * Requires privilege and cannot conflict with exists system interfaces.
     *
     * Forced if gVisor not included in the build.
     */
    system_interface: Option[String] = None,
    /** Custom interface name for system interface. */
    interface_name: Option[String] = None,
    /** Try to enable generic segmentation offload. */
    gso: Option[Boolean] = None,
    /** WireGuard worker count. CPU count is used by default. */
    workers: Option[Int] = None,
    /** WireGuard MTU. 1408 will be used if empty. */
    mtu: Option[Int] = None,
    /** Enabled network. One of tcp udp. Both is enabled by default. */
    network: Option[SingBoxNetwork] = None,
    /** Dial Fields [[DialFieldsMixin]] */
    detour: Option[OutboundLike] = None,
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
  ) extends ProtocolOutbound("wireguard") with DialFieldsMixin
}

enum GroupOutbound(`type`: GroupOutboundType) {

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
    outbounds: Seq[OutboundLike],
    default: Option[OutboundLike] = None,
    interrupt_exist_connections: Option[Boolean] = None,
  ) extends GroupOutbound("selector")

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
    outbounds: Seq[OutboundLike],
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
  ) extends GroupOutbound("urltest")

  // @classmethod
  // def from_uniproxy(cls, protocol: UrlTestGroup, **kwargs) -> UrlTestOutbound:
  //     return cls(
  //         tag=protocol.name,
  //         outbounds=[str(i) for i in protocol.proxies] if protocol.proxies else [],
  //         url=protocol.url,
  //         interval=f"{protocol.interval}s" if protocol.interval else None,
  //         tolerance=protocol.tolerance,
  //     )

}

type Outbound = ProtocolOutbound | GroupOutbound

// extension

// SingBoxProtocolOutbound = (
//     DirectOutbound
//     | BlockOutbound
//     | DnsOutbound
//     | ShadowsocksOutbound
//     | VmessOutbound
//     | TrojanOutbound
//     | WireguardOutbound
// )
// SingBoxGroupOutbound = SelectorOutbound | UrlTestOutbound
// SingBoxOutbound = SingBoxProtocolOutbound | SingBoxGroupOutbound

// _SINGBOX_REGISTERED_PROTOCOLS: Mapping[ProtocolType, SingBoxProtocolOutbound] = {
//     # "direct": DirectOutbound,
//     # "block": BlockOutbound,
//     # "dns": DnsOutbound,
//     "shadowsocks": ShadowsocksOutbound,
//     "vmess": VmessOutbound,
//     "trojan": TrojanOutbound,
//     "wireguard": WireguardOutbound,
// }
// _SINGBOX_REGISTERED_PROXY_GROUPS: Mapping[GroupType, SingBoxGroupOutbound] = {
//     "select": SelectorOutbound,
//     "url-test": UrlTestOutbound,
//     "load-balance": PseudoLoadBalanceOutbound,
//     "fallback": PseudoFallbackOutbound,
// }

// def make_outbound_from_uniproxy(
//     protocol: UniproxyProtocol | UniproxyProxyGroup, **kwargs
// ) -> SingBoxOutbound:
//     if protocol.type in _SINGBOX_REGISTERED_PROTOCOLS.keys():
//         return _SINGBOX_REGISTERED_PROTOCOLS[
//             cast(UniproxyProtocol, protocol).type
//         ].from_uniproxy(protocol, **kwargs)  # type: ignore
//     elif protocol.type in _SINGBOX_REGISTERED_PROXY_GROUPS.keys():
//         return _SINGBOX_REGISTERED_PROXY_GROUPS[
//             cast(UniproxyProxyGroup, protocol).type
//         ].from_uniproxy(protocol, **kwargs)  # type: ignore
//     else:
//         raise ValueError(
//             f"Unsupported or not implemented protocol type {protocol.type}"
//         )

export ProtocolOutbound.*
export GroupOutbound.*
