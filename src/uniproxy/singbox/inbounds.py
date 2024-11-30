from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import NetworkCIDR, ShadowsocksCipher

from attrs import define, frozen

from uniproxy.common import User

from .base import BaseInbound as SingBoxInbound
from .route import BaseRuleSet
from .shared import (
    BaseTransport,
    Fallback,
    InboundMultiplex,
    InboundTLS,
    ListenFieldsMixin,
    Platform,
)
from .typing import FallbackAlpn, SingBoxNetwork, TunStack

__all__ = (
    "DirectInbound",
    "HTTPInbound",
    "Socks5Inbound",
    "ShadowsocksInbound",
    "TrojanInbound",
    "TuicInbound",
    "TunInbound",
    #
    "User",
    "TuicUser",
)


@define(slots=False)
class DirectMixin:
    """
    {
    "type": "direct",
    "tag": "direct-in",

    ... // Listen fields

    "network": "udp",
    "override_address": "1.0.0.1",
    "override_port": 53
    }
    """

    network: SingBoxNetwork | None = None
    """
    Listen network, one of `tcp`, `udp`.

    Both if empty.
    """
    override_address: str | None = None
    """Override the connection destination address."""
    override_port: int | None = None
    """Override the connection destination port."""

    type: Literal["direct"] = "direct"


@define
class DirectInbound(ListenFieldsMixin, DirectMixin, SingBoxInbound): ...  # type: ignore[misc]


@define
class HTTPInbound(SingBoxInbound):
    users: Sequence[User] | None = None
    tls: InboundTLS | None = None
    set_system_proxy: bool | None = None
    type: Literal["http"] = "http"


@define
class Socks5Inbound(SingBoxInbound):
    users: Sequence[User] | None = None
    type: Literal["socks"] = "socks"


@define(slots=False)
class ShadowsocksMixin:
    """
    Structure

    ```json
    {
      "type": "shadowsocks",
      "tag": "ss-in",

      ... // Listen Fields

      "method": "2022-blake3-aes-128-gcm",
      "password": "8JCsPssfgS8tiRwiMlhARg==",
      "multiplex": {}
    }

    ```


    Multi-User Structure

    ```json
    {
      "method": "2022-blake3-aes-128-gcm",
      "password": "8JCsPssfgS8tiRwiMlhARg==",
      "users": [
        {
          "name": "sekai",
          "password": "PCD2Z4o12bKUoFa3cC97Hw=="
        }
      ],
      "multiplex": {}
    }

    ```

    Relay Structure

    ```json
    {
      "type": "shadowsocks",
      "method": "2022-blake3-aes-128-gcm",
      "password": "8JCsPssfgS8tiRwiMlhARg==",
      "destinations": [
        {
          "name": "test",
          "server": "example.com",
          "server_port": 8080,
          "password": "PCD2Z4o12bKUoFa3cC97Hw=="
        }
      ],
      "multiplex": {}
    }
    ```
    """

    method: ShadowsocksCipher
    """
    |Method                       |Key Length|
    |-----------------------------|----------|
    |2022-blake3-aes-128-gcm      |16        |
    |2022-blake3-aes-256-gcm      |32        |
    |2022-blake3-chacha20-poly1305|32        |
    |none                         |/         |
    |aes-128-gcm                  |/         |
    |aes-192-gcm                  |/         |
    |aes-256-gcm                  |/         |
    |chacha20-ietf-poly1305       |/         |
    |xchacha20-ietf-poly1305      |/         |
    """

    password: str
    """Password for the Shadowsocks server."""

    network: SingBoxNetwork = None
    """
    Listen network, one of `tcp` `udp`.

    Both if empty.
    """

    users: Sequence[User] | None = None
    """Multi-user configuration."""

    # destinations: Sequence[dict] | None = None
    # """Relay configuration."""

    multiplex: InboundMultiplex | None = None
    """
    See [Multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex#inbound) for details.
    """


@define
class ShadowsocksInbound(ListenFieldsMixin, ShadowsocksMixin, SingBoxInbound):  # type: ignore[misc]
    type: Literal["shadowsocks"] = "shadowsocks"


@define(slots=False)
class TrojanMixin:
    """
    ```json
    {
      "type": "trojan",
      "tag": "trojan-in",

      ... // Listen Fields

      "users": [
        {
          "name": "sekai",
          "password": "8JCsPssfgS8tiRwiMlhARg=="
        }
      ],
      "tls": {},
      "fallback": {
        "server": "127.0.0.1",
        "server_port": 8080
      },
      "fallback_for_alpn": {
        "http/1.1": {
          "server": "127.0.0.1",
          "server_port": 8081
        }
      },
      "multiplex": {},
      "transport": {}
    }
    ```
    """

    users: Sequence[User]
    """Trojan users."""

    tls: InboundTLS
    """TLS configuration, see [TLS](https://sing-box.sagernet.org/configuration/shared/tls/#inbound)."""

    fallback: Fallback | None = None
    """
    There is no evidence that GFW detects and blocks Trojan servers based on HTTP responses, and opening the standard http/s port on the server is a much bigger signature.

    Fallback server configuration. Disabled if `fallback` and `fallback_for_alpn` are empty.
    """

    fallback_for_alpn: FallbackAlpn | None = None
    """
    Fallback server configuration for specified ALPN.

    If not empty, TLS fallback requests with ALPN not in this table will be rejected.
    """

    multiplex: InboundMultiplex | None = None
    """
    See [Multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex#inbound) for details.
    """

    transport: BaseTransport | None = None
    """
    V2Ray Transport configuration, see [V2Ray Transport](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/).
    """


@define
class TrojanInbound(ListenFieldsMixin, TrojanMixin, SingBoxInbound):  # type: ignore[misc]
    type: Literal["trojan"] = "trojan"


@frozen
class TuicUser:
    uuid: str
    """TUIC user uuid"""
    name: str | None = None
    """TUIC user name"""
    password: str | None = None
    """TUIC user password"""


@define(slots=False)
class TuicMixin:
    """
    ```json
    {
      "type": "tuic",
      "tag": "tuic-in",

      ... // Listen Fields

      "users": [
        {
          "name": "sekai",
          "uuid": "059032A9-7D40-4A96-9BB1-36823D848068",
          "password": "hello"
        }
      ],
      "congestion_control": "cubic",
      "auth_timeout": "3s",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {}
    }
    ```
    """

    users: Sequence[TuicUser]
    """TUIC users"""

    tls: InboundTLS
    """TLS configuration"""

    congestion_control: Literal["cubic", "new_reno", "bbr"] | None = None
    """
    QUIC congestion control algorithm One of: `cubic`, `new_reno`, `bbr`.

    `cubic` is used by default.
    """

    auth_timeout: str | None = None
    """
    How long the server should wait for the client to send the authentication command

    `3s` is used by default.
    """

    zero_rtt_handshake: bool | None = None
    """
    Enable 0-RTT QUIC connection handshake on the client side
    This is not impacting much on the performance, as the protocol is fully multiplexed

    > [!WARN]
    >
    > Disabling this is highly recommended, as it is vulnerable to replay attacks.
    > See [Attack of the clones](https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones).
    """

    heartbeat: str | None = None
    """
    Interval for sending heartbeat packets for keeping the connection alive

    `10s` is used by default.
    """


@define
class TuicInbound(ListenFieldsMixin, TuicMixin, SingBoxInbound):  # type: ignore[misc]
    type: Literal["tuic"] = "tuic"


@define
class TunMixin:
    """
    ```json
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": [
        "172.18.0.1/30",
        "fdfe:dcba:9876::1/126"
      ],
      "mtu": 9000,
      "auto_route": true,
      "iproute2_table_index": 2022,
      "iproute2_rule_index": 9000,
      "auto_redirect": false,
      "auto_redirect_input_mark": "0x2023",
      "auto_redirect_output_mark": "0x2024",
      "strict_route": true,
      "route_address": [
        "0.0.0.0/1",
        "128.0.0.0/1",
        "::/1",
        "8000::/1"
      ],
      "route_exclude_address": [
        "192.168.0.0/16",
        "fc00::/7"
      ],
      "route_address_set": [
        "geoip-cloudflare"
      ],
      "route_exclude_address_set": [
        "geoip-cn"
      ],
      "endpoint_independent_nat": false,
      "udp_timeout": "5m",
      "stack": "system",
      "include_interface": [
        "lan0"
      ],
      "exclude_interface": [
        "lan1"
      ],
      "include_uid": [
        0
      ],
      "include_uid_range": [
        "1000-99999"
      ],
      "exclude_uid": [
        1000
      ],
      "exclude_uid_range": [
        "1000-99999"
      ],
      "include_android_user": [
        0,
        10
      ],
      "include_package": [
        "com.android.chrome"
      ],
      "exclude_package": [
        "com.android.captiveportallogin"
      ],
      "platform": {
        "http_proxy": {
          "enabled": false,
          "server": "127.0.0.1",
          "server_port": 8080,
          "bypass_domain": [],
          "match_domain": []
        }
      },

      // Deprecated
      "gso": false,
      "inet4_address": [
        "172.19.0.1/30"
      ],
      "inet6_address": [
        "fdfe:dcba:9876::1/126"
      ],
      "inet4_route_address": [
        "0.0.0.0/1",
        "128.0.0.0/1"
      ],
      "inet6_route_address": [
        "::/1",
        "8000::/1"
      ],
      "inet4_route_exclude_address": [
        "192.168.0.0/16"
      ],
      "inet6_route_exclude_address": [
        "fc00::/7"
      ],

      ... // Listen Fields
    }
    ```
    """

    address: Sequence[NetworkCIDR] | None = None
    """IPv4 and IPv6 prefix (CIDR mark) for the tun interface."""
    inet4_address: str | Sequence[str] | None = None
    """`inet4_address` is merged to `address` and will be removed in sing-box 1.11.0."""
    inet6_address: str | Sequence[str] | None = None
    """`inet6_address` is merged to `address` and will be removed in sing-box 1.11.0."""
    interface_name: str | None = None
    """Virtual device name, automatically selected if empty."""
    mtu: int | None = None
    """The maximum transmission unit."""
    gso: bool | None = None
    """
    > ![NOTE]
    >
    > Only supported on Linux with `auto_route` enabled.

    Enable generic segmentation offload.
    """
    auto_route: bool | None = None
    """
    Set the default route to the Tun.

    > [!WARN]
    > To avoid traffic loopback, set `route.auto_detect_interface` or
    > `route.default_interface` or `outbound.bind_interface`

    By default, VPN takes precedence over tun. To make tun go through VPN,
    enable `route.override_android_vpn`.
    """
    iproute2_table_index: int | None = None
    """
    Linux iproute2 table index generated by `auto_route`.

    `2022` is used by default.
    """
    iproute2_rule_index: int | None = None
    """
    Linux iproute2 rule start index generated by `auto_route`.

    `9000` is used by default.
    """
    auto_redirect: bool | None = None
    """
    > ![WARN] Only supported on Linux with `auto_route` enabled.

    Automatically configure iptables/nftables to redirect connections.

    *In Android*：

    Only local connections are forwarded. To share your VPN connection
    over hotspot or repeater, use [VPNHotspot](https://github.com/Mygod/VPNHotspot).

    *In Linux*:

    `auto_route` with `auto_redirect` now works as expected on routers
    **without intervention**.
    """
    auto_redirect_input_mark: str | None = None
    """
    Connection input mark used by `route_address_set` and
    `route_exclude_address_set`.

    `0x2023` is used by default.
    """
    auto_redirect_output_mark: str | None = None
    """
    Connection output mark used by `route_address_set` and
    `route_exclude_address_set`.

    `0x2024` is used by default.
    """
    strict_route: bool | None = None
    """
    Enforce strict routing rules when `auto_route` is enabled:

    *In Linux*:

    * Let unsupported network unreachable
    * Make ICMP traffic route to tun instead of upstream interfaces
    * Route all connections to tun

    It prevents IP address leaks and makes DNS hijacking work on Android.

    *In Windows*:

    * Add firewall rules to prevent DNS leak caused by
    Windows' [ordinary multihomed DNS resolution behavior](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29)

    It may prevent some applications (such as VirtualBox) from working
    properly in certain situations.
    """
    route_address: Sequence[str] | None = None
    """Use custom routes instead of default when `auto_route` is enabled."""
    route_exclude_address: Sequence[str] | None = None
    """Exclude custom routes when `auto_route` is enabled."""
    route_address_set: Sequence[str | BaseRuleSet] | None = None
    """
    > ![NOTE]
    >
    > Only supported on Linux with nftables and requires `auto_route` and
    > `auto_redirect` enabled.

    Add the destination IP CIDR rules in the specified rule-sets to
    the firewall. Unmatched traffic will bypass the sing-box routes.

    Conflict with `route.default_mark` and `[dialOptions].routing_mark`.
    """
    route_exclude_address_set: Sequence[str | BaseRuleSet] | None = None
    """
    > ![NOTE]
    >
    > Only supported on Linux with nftables and requires `auto_route` and
    > `auto_redirect` enabled.

    Add the destination IP CIDR rules in the specified rule-sets to the
    firewall. Matched traffic will bypass the sing-box routes.

    Conflict with `route.default_mark` and `[dialOptions].routing_mark`.
    """
    endpoint_independent_nat: bool | None = None
    """
    This item is only available on the gvisor stack, other stacks are
    endpoint-independent NAT by default.

    Enable endpoint-independent NAT.

    Performance may degrade slightly, so it is not recommended to enable on
    when it is not needed.
    """
    udp_timeout: float | None = None
    """UDP NAT expiration time in seconds, default is 300 (5 minutes)."""
    stack: TunStack | None = None
    """
    TCP/IP stack.

    | Stack    | Description                                                                                           |
    |----------|-------------------------------------------------------------------------------------------------------|
    | `system` | Perform L3 to L4 translation using the system network stack                                           |
    | `gvisor` | Perform L3 to L4 translation using [gVisor](https://github.com/google/gvisor)'s virtual network stack |
    | `mixed`  | Mixed `system` TCP stack and `gvisor` UDP stack                                                       |

    Defaults to the `mixed` stack if the gVisor build tag is enabled, otherwise defaults to the `system` stack.
    """
    include_interface: Sequence[str] | None = None
    """
    > ![NOTE]
    > Interface rules are only supported on Linux and require `auto_route`.

    Limit interfaces in route. Not limited by default.

    Conflict with `exclude_interface`.
    """
    exclude_interface: Sequence[str] | None = None
    """
    > ![NOTE]
    > When `strict_route` enabled, return traffic to excluded interfaces will
    > not be automatically excluded, so add them as well
    > (example: `br-lan` and `pppoe-wan`).

    Exclude interfaces in route.

    Conflict with `include_interface`.
    """
    include_uid: Sequence[int] | None = None
    """
    > ![NOTE]
    >
    > UID rules are only supported on Linux and require `auto_route`.

    Limit users in route. Not limited by default.
    """
    include_uid_range: Sequence[str] | None = None
    """Limit users in route, but in range."""
    exclude_uid: Sequence[int] | None = None
    """Exclude users in route."""
    exclude_uid_range: Sequence[str] | None = None
    """Exclude users in route, but in range."""
    include_android_user: Sequence[int] | None = None
    """
    > ![NOTE]
    >
    > Android user and package rules are only supported on Android
    > and require `auto_route`.

    Limit android users in route.

    | Common user  | ID |
    |--------------|----|
    | Main         | 0  |
    | Work Profile | 10 |
    """
    include_package: Sequence[str] | None = None
    """Limit android packages in route."""
    exclude_package: Sequence[str] | None = None
    """Exclude android packages in route."""
    platform: Platform | None = None
    """Platform-specific settings, provided by client applications."""

    sniff: bool | None = None


@define
class TunInbound(ListenFieldsMixin, TunMixin, SingBoxInbound):  # type: ignore[misc]
    type: Literal["tun"] = "tun"

    def __attrs_post_init__(self):
        if self.include_interface and self.exclude_interface:
            raise ValueError(
                "Option 'include_interface' and 'exclude_interface' are mutually conflicting."
            )
