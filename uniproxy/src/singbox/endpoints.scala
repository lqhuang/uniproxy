package singbox

import com.comcast.ip4s.{Host, IpAddress, Ipv4Address, Ipv6Address, Port}
import upickle.default.ReadWriter

import uniproxy.typing.{ShadowsocksCipher, VmessCipher}
import uniproxy.singbox.abc.{Outbound, OutboundLike}
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

import uniproxy.singbox.typing.EndpointType

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

enum Endpoint(`type`: EndpointType) derives ReadWriter {

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
    // domain_strategy: Option[DomainStrategy] = None,
    fallback_delay: Option[String] = None,
  ) extends Endpoint(EndpointType.wireguard) with DialFieldsMixin
}
