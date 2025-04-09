package uniproxy
package singbox
package inbounds

import com.comcast.ip4s.{Host, Hostname, Port}

import uniproxy.typing.{NetworkCIDR, ShadowsocksCipher}

import uniproxy.singbox.route.RuleSet
import uniproxy.singbox.shared.{InboundMultiplex, ListenFieldsMixin}
import uniproxy.singbox.typing.{
  Fallback,
  FallbackAlpn,
  InboundType,
  SingBoxNetwork,
  TunStack,
  User,
}
import uniproxy.singbox.abc.{AbstractInbound, InboundLike, OutboundLike, RuleSetLike}
import uniproxy.singbox.transports.Transport
import uniproxy.singbox.tls.InboundTLS

case class TuicUser(
  uuid: String,
  /** TUIC user uuid */
  name: Option[String] = None,
  /** TUIC user name */
  password: Option[String] = None,
  /** TUIC user password */
)

case class PlatformHttpProxy(
  /** HTTP proxy server address. */
  server: Host,
  /** HTTP proxy server port. */
  server_port: Port,
  /** Enable system HTTP proxy. */
  enabled: Option[Boolean] = None,
  /**
   * > [!WARN]
   *
   * > On Apple platforms, [[bypass_domain]] items matches hostname
   * **suffixes**.
   *
   * Hostnames that bypass the HTTP proxy.
   */
  bypass_domain: Option[Seq[Hostname]] = None,

  /**
   * > [!WARN]
   *
   * > Only supported in graphical clients on Apple platforms.
   *
   * Hostnames that use the HTTP proxy.
   */
  match_domain: Option[Seq[Hostname]] = None,
)

case class Platform(
  /** System HTTP proxy settings. */
  http_proxy: PlatformHttpProxy,
)

enum Inbound(`type`: InboundType) extends AbstractInbound {

  case DirectInbound(
    tag: String,
    listen: Host,
    listen_port: Port,
    /** Listen network, one of `tcp`, `udp`. Both if empty. */
    network: Option[SingBoxNetwork] = None,
    /** Override the connection destination address. */
    override_address: Option[String] = None,
    /** Override the connection destination port. */
    override_port: Option[Int] = None,
    /** Listen Fields (except `listen` and `listen_port) */
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    udp_timeout: Option[String] = None,
    detour: Option[OutboundLike] = None,
  ) extends Inbound("direct") with ListenFieldsMixin

  case HTTPInbound(
    tag: String,
    listen: Host,
    listen_port: Port,
    users: Option[Seq[User]] = None,
    tls: Option[InboundTLS] = None,
    set_system_proxy: Option[Boolean] = None,
    /** Listen Fields (except `listen` and `listen_port) */
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    udp_timeout: Option[String] = None,
    detour: Option[OutboundLike] = None,
  ) extends Inbound("http") with ListenFieldsMixin

  /**
   * SOCKS
   *
   * `socks` inbound is a socks4, socks4a, socks5 server.
   * ```json
   * {
   * "type": "socks",
   * "tag": "socks-in",
   *
   * ... // Listen Fields
   *
   * "users": [
   * {
   * "username": "admin",
   * "password": "admin"
   * }
   * ]
   * }
   * ```
   */
  case Socks5Inbound(
    tag: String,
    listen: Host,
    listen_port: Port,
    /** SOCKS users. No authentication required if empty. */
    users: Option[Seq[User]] = None,
    /** Listen Fields (except `listen` and `listen_port) */
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    udp_timeout: Option[String] = None,
    detour: Option[OutboundLike] = None,
  ) extends Inbound("socks") with ListenFieldsMixin

  case ShadowsocksInbound(
    tag: String,
    listen: Host,
    listen_port: Port,
    method: ShadowsocksCipher,
    password: String,
    /** Password for the Shadowsocks server. */
    /** Listen network, one of `tcp` `udp`. Both if empty. */
    network: Option[SingBoxNetwork] = None,
    /** Multi-user configuration. */
    users: Option[Seq[User]] = None,
    /**
     * See
     * [Multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex#inbound)
     * for details.
     */
    multiplex: Option[InboundMultiplex] = None,
    /** Listen Fields (except `listen` and `listen_port) */
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    udp_timeout: Option[String] = None,
    detour: Option[OutboundLike] = None,
  ) extends Inbound("shadowsocks") with ListenFieldsMixin

  case TrojanInbound(
    tag: String,
    listen: Host,
    listen_port: Port,
    /** Trojan users. */
    users: Seq[User],
    /**
     * TLS configuration, see
     * [TLS](https://sing-box.sagernet.org/configuration/shared/tls/#inbound).
     */
    tls: InboundTLS,
    /**
     * Fallback server configuration. Disabled if `fallback` and
     * `fallback_for_alpn` are empty.
     */
    fallback: Option[Fallback] = None,
    /** Fallback server configuration for specified ALPN. */
    fallback_for_alpn: Option[FallbackAlpn] = None,
    /**
     * See
     * [Multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex#inbound)
     * for details.
     */
    multiplex: Option[InboundMultiplex] = None,
    /**
     * V2Ray Transport configuration, see [V2Ray
     * Transport](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/).
     */
    transport: Option[Transport] = None,
    /** Listen Fields (except `listen` and `listen_port) */
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    udp_timeout: Option[String] = None,
    detour: Option[OutboundLike] = None,
  ) extends Inbound("trojan") with ListenFieldsMixin

  case TuicInbound(
    tag: String,
    listen: Host,
    listen_port: Port,
    /** TUIC users */
    users: Seq[TuicUser],
    /** TLS configuration */
    tls: InboundTLS,
    /**
     * QUIC congestion control algorithm One of: `cubic`, `new_reno`, `bbr`.
     * `cubic` is used by default.
     */
    congestion_control: Option[String] = None,
    /**
     * How long the server should wait for the client to send the authentication
     * command. `3s` is used by default.
     */
    auth_timeout: Option[String] = None,
    /**
     * Enable 0-RTT QUIC connection handshake on the client side. Disabling this
     * is highly recommended, as it is vulnerable to replay attacks.
     */
    zero_rtt_handshake: Option[Boolean] = None,
    /**
     * Interval for sending heartbeat packets for keeping the connection alive.
     * `10s` is used by default.
     */
    heartbeat: Option[String] = None,
    /** Listen Fields (except `listen` and `listen_port) */
    tcp_fast_open: Option[Boolean] = None,
    tcp_multi_path: Option[Boolean] = None,
    udp_fragment: Option[Boolean] = None,
    udp_timeout: Option[String] = None,
    detour: Option[OutboundLike] = None,
  ) extends Inbound("tuic") with ListenFieldsMixin

  case class TunMixin(
  )

  case TunInbound(
    tag: String,
    /** IPv4 and IPv6 prefix (CIDR mark) for the tun interface. */
    address: Option[Seq[NetworkCIDR]] = None,
    /** Virtual device name, automatically selected if empty. */
    interface_name: Option[String] = None,
    /** The maximum transmission unit. */
    mtu: Option[Int] = None,
    /**
     * Set the default route to the Tun.
     *
     * To avoid traffic loopback, set `route.auto_detect_interface` or
     * `route.default_interface` or `outbound.bind_interface`
     */
    auto_route: Option[Boolean] = None,
    /**
     * Linux iproute2 table index generated by `auto_route`. `2022` is used by
     * default.
     */
    iproute2_table_index: Option[Int] = None,
    /**
     * Linux iproute2 rule start index generated by `auto_route`. `9000` is used
     * by default.
     */
    iproute2_rule_index: Option[Int] = None,
    /**
     * > Only supported on Linux with auto_route enabled.
     *
     * Automatically configure iptables/nftables to redirect connections.
     *
     * In Android:
     *
     * Only local IPv4 connections are forwarded. To share your VPN connection
     * over hotspot or repeater, use [[VPNHotspot]].
     *
     * In Linux:
     *
     * `auto_route` with `auto_redirect` works as expected on routers without
     * intervention.
     */
    auto_redirect: Option[Boolean] = None,
    /**
     * Connection input mark used by `route_address_set` and
     * `route_exclude_address_set`.
     *
     * `0x2023` is used by default.
     */
    auto_redirect_input_mark: Option[String] = None,
    /**
     * Connection output mark used by `route_address_set` and
     * `route_exclude_address_set`.
     *
     * `0x2024` is used by default.
     */
    auto_redirect_output_mark: Option[String] = None,
    /**
     * Enforce strict routing rules when `auto_route` is enabled.
     *
     * In Linux:
     *
     *   - Let unsupported network unreachable
     *   - Make ICMP traffic route to tun instead of upstream interfaces
     *   - Route all connections to tun
     *
     * It prevents IP address leaks and makes DNS hijacking work on Android.
     *
     * In Windows:
     *
     *   - Add firewall rules to prevent DNS leak caused by Windows' [ordinary
     *     multihomed DNS resolution
     *     behavior](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29)
     *
     * It may prevent some applications (such as VirtualBox) from working
     * properly in certain situations.
     */
    strict_route: Option[Boolean] = None,
    /** Use custom routes instead of default when `auto_route` is enabled. */
    route_address: Option[Seq[String]] = None,
    /** Exclude custom routes when `auto_route` is enabled. */
    route_exclude_address: Option[Seq[String]] = None,
    /**
     * > Only supported on Linux with nftables and requires `auto_route` and
     * `auto_redirect` enabled.
     *
     * Add the destination IP CIDR rules in the specified rule-sets to the
     * firewall. Unmatched traffic will bypass the sing-box routes.
     *
     * Conflict with `route.default_mark` and `[dialOptions].routing_mark`.
     */
    route_address_set: Option[Seq[RuleSetLike]] = None,
    /**
     * * > Only supported on Linux with nftables and requires `auto_route` and
     * `auto_redirect` enabled.
     *
     * Add the destination IP CIDR rules in the specified rule-sets to the
     * firewall. Matched traffic will bypass the sing-box routes.
     *
     * * Conflict with `route.default_mark` and `[dialOptions].routing_mark`.
     */
    route_exclude_address_set: Option[Seq[RuleSetLike]] = None,
    /**
     * > This item is only available on the gvisor stack, other stacks are
     * endpoint-independent NAT by default.
     *
     * Enable endpoint-independent NAT.
     *
     * Performance may degrade slightly, so it is not recommended to enable on
     * when it is not needed.
     */
    endpoint_independent_nat: Option[Boolean] = None,
    /**
     * UDP NAT expiration time
     *
     * `5m` will be used by default.
     */
    udp_timeout: Option[Float] = None,
    /**
     * TCP/IP stack.
     *
     * | Stack    | Description                                                       |
     * |:---------|:------------------------------------------------------------------|
     * | `system` | Perform L3 to L4 translation using the system network stack       |
     * | `gvisor` | Perform L3 to L4 translation using gVisor's virtual network stack |
     * | `mixed`  | Mixed `system` TCP stack and `gvisor` UDP stack                   |
     *
     * Defaults to the `mixed` stack if the gVisor build tag is enabled,
     * otherwise defaults to the `system` stack.
     */
    stack: Option[TunStack] = None,
    /**
     * > Interface rules are only supported on Linux and require `auto_route`.
     *
     * Limit interfaces in route. Not limited by default.
     *
     * Conflict with `exclude_interface`.
     */
    include_interface: Option[Seq[String]] = None,
    /**
     * > When `strict_route` enabled, return traffic to excluded interfaces will
     * not be automatically excluded, so add them as well (example: `br-lan` and
     * `pppoe-wan`).
     *
     * Exclude interfaces in route.
     *
     * Conflict with `include_interface`.
     */
    exclude_interface: Option[Seq[String]] = None,
    /**
     * > UID rules are only supported on Linux and require `auto_route`.
     *
     * Limit users in route. Not limited by default.
     */
    include_uid: Option[Seq[Int]] = None,
    /** Limit users in route, but in range. */
    include_uid_range: Option[Seq[String]] = None,
    /** Exclude users in route. */
    exclude_uid: Option[Seq[Int]] = None,
    /** Exclude users in route, but in range. */
    exclude_uid_range: Option[Seq[String]] = None,
    /**
     * > Android user and package rules are only supported on Android and
     * require auto_route.
     *
     * Limit android users in route.
     */
    include_android_user: Option[Seq[Int]] = None,
    /** Limit android packages in route. */
    include_package: Option[Seq[String]] = None,
    /** Exclude android packages in route. */
    exclude_package: Option[Seq[String]] = None,
    /** Platform-specific settings, provided by client applications. */
    platform: Option[Platform] = None,
    sniff: Option[Boolean] = None,

    /** supported Listen Fields */
    detour: Option[OutboundLike] = None,
  ) extends Inbound("tun")

  // def __attrs_post_init__(): Unit = {
  //   if include_interface.isDefined && exclude_interface.isDefined then {
  //     throw new ValueError(
  //       "Option 'include_interface' and 'exclude_interface' are mutually conflicting.",
  //     )
  //   }
  // }

}

export Inbound.*
