from __future__ import annotations

from typing import Any, Literal, Mapping, Sequence, TypeGuard, cast
from uniproxy.typing import (
    GroupType,
    IPAddress,
    ProtocolType,
    ServerAddress,
    ShadowsocksCipher,
    VmessCipher,
)

from attrs import define, field

from uniproxy.protocols import (
    ShadowsocksObfsPlugin,
    ShadowsocksProtocol,
    TrojanProtocol,
    UniproxyProtocol,
    VmessProtocol,
)
from uniproxy.proxy_groups import (
    LoadBalanceGroup,
    SelectGroup,
    UniproxyProxyGroup,
    UrlTestGroup,
)
from uniproxy.utils import map_to_str

from .base import BaseOutbound
from .dns import BaseDnsServer
from .shared import BaseTransport, DialFieldsMixin, OutboundMultiplex, OutboundTLS
from .typing import SingBoxNetwork

__all__ = (
    "DirectOutbound",
    "ShadowsocksOutbound",
    "VmessOutbound",
    "TrojanOutbound",
    "Peer",
    "WireguardOutbound",
    "SelectorOutbound",
    "UrlTestOutbound",
)


@define(slots=False)
class DirectMixin:
    override_address: ServerAddress | None = None
    """Override the connection destination address."""
    override_port: int | None = None
    """Override the connection destination port."""
    proxy_protocol: Literal[1, 2] | None = None
    """
    Write [Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
    in the connection header. Protocol value can be `1` or `2`.
    """


@define
class DirectOutbound(DialFieldsMixin, DirectMixin, BaseOutbound):  # type: ignore[misc]
    """
    Examples:

    ```json
    {
      "type": "direct",
      "tag": "direct-out",

      "override_address": "1.0.0.1",
      "override_port": 53,
      "proxy_protocol": 0,

      ... // Dial Fields
    }
    ```
    """

    type: Literal["direct"] = "direct"


@define(slots=False)
class ShadowsocksMixin:
    server: ServerAddress
    """The server address."""
    server_port: int
    """The server port."""
    method: ShadowsocksCipher
    """Encryption methods."""
    password: str
    """The shadowsocks password."""
    plugin: Literal["obfs-local", "v2ray-plugin"] | str | None = None
    """Shadowsocks SIP003 plugin, implemented in internal."""
    plugin_opts: str | None = None
    """Shadowsocks SIP003 plugin options."""
    network: SingBoxNetwork | None = None
    """Enabled network. One of `tcp`, `udp`. Both is enabled by default."""
    udp_over_tcp: bool | None = None
    """UDP over TCP configuration. Conflict with `multiplex`."""
    multiplex: OutboundMultiplex | None = None
    """See Multiplex for details."""

    def __attrs_post_init__(self):
        if self.udp_over_tcp and self.multiplex:
            raise ValueError(
                "Option 'udp_over_tcp' and 'multiplex' cannot be used together"
            )


@define
class ShadowsocksOutbound(DialFieldsMixin, ShadowsocksMixin, BaseOutbound):  # type: ignore[misc]
    """

    Examples:

    ```json
    {
        "type": "shadowsocks",
        "tag": "ss-out",

        "server": "127.0.0.1",
        "server_port": 1080,
        "method": "2022-blake3-aes-128-gcm",
        "password": "8JCsPssfgS8tiRwiMlhARg==",
        "plugin": "",
        "plugin_opts": "",
        "network": "udp",
        "udp_over_tcp": false | {},
        "multiplex": {},

        ... // Dial Fields
    }
    ```
    """

    type: Literal["shadowsocks"] = "shadowsocks"

    @classmethod
    def from_uniproxy(
        cls, protocol: ShadowsocksProtocol, **kwargs
    ) -> ShadowsocksOutbound:
        if protocol.plugin is not None:
            if protocol.plugin.command in {"obfs-local", "obfs"}:
                p = cast(ShadowsocksObfsPlugin, protocol.plugin)
                plugin = "obfs-local"
                plugin_opts = f"obfs={p.obfs};obfs-host={p.obfs_host}"
            elif protocol.plugin.command == "v2ray-plugin":
                raise NotImplementedError("v2ray-plugin plugin is not implemented yet")
            else:
                raise NotImplementedError(
                    f"Plugin {protocol.plugin.command} for SingBox Shadowsocks protocol is not supported yet for now"
                )
        else:
            plugin = None
            plugin_opts = None

        return cls(
            tag=protocol.name,
            server=protocol.server,
            server_port=protocol.port,
            method=protocol.method,
            password=protocol.password,
            network=None if protocol.network == "tcp_and_udp" else protocol.network,
            plugin=plugin,
            plugin_opts=plugin_opts,
            **kwargs,
        )


@define(slots=False)
class VmessMixin:
    tag: str
    server: ServerAddress
    server_port: int
    uuid: str
    security: VmessCipher
    alter_id: int | None = None
    global_padding: bool | None = None
    authenticated_length: bool | None = True
    network: SingBoxNetwork | None = None
    tls: OutboundTLS | None = None
    packet_encoding: Literal["packetaddr", "xudp"] | None = None
    transport: BaseTransport | None = None
    multiplex: OutboundMultiplex | None = None


@define
class VmessOutbound(DialFieldsMixin, VmessMixin, BaseOutbound):  # type: ignore[misc]
    type: Literal["vmess"] = "vmess"

    @classmethod
    def from_uniproxy(cls, protocol: VmessProtocol, **kwargs) -> VmessOutbound:
        # transport_mapping = {
        #     "ws": "ws",
        #     "h2": "h2",
        #     "quic": "quic",
        #     "httpupgrade": NotImplementedError("httpupgrade"),
        # }
        if protocol.transport is not None:
            # transport = transport_mapping[protocol.transport]
            raise NotImplementedError(
                f"unsupported transport type {protocol.transport.type} for now"
            )

        return cls(
            tag=protocol.name,
            server=protocol.server,
            server_port=protocol.port,
            uuid=protocol.uuid,
            security=protocol.security,
            alter_id=protocol.alter_id,
            network=None if protocol.network == "tcp_and_udp" else protocol.network,
            tls=(
                None
                if protocol.tls is None
                else OutboundTLS.from_uniproxy(protocol.tls)
            ),
            **kwargs,
        )


@define(slots=False)
class TrojanMixin:
    server: ServerAddress
    """The server address."""
    server_port: int
    """The server port."""
    password: str
    """The Trojan password."""
    tls: OutboundTLS | None = None
    """TLS configuration, see [[TLS]]."""
    multiplex: OutboundMultiplex | None = None
    """See [[Multiplex]] for details."""
    transport: BaseTransport | None = None
    """V2Ray Transport configuration, see V2Ray Transport."""


@define
class TrojanOutbound(DialFieldsMixin, TrojanMixin, BaseOutbound):  # type: ignore[misc]
    """
    Examples:

    ```json
    {
        "type": "trojan",
        "tag": "trojan-out",

        "server": "127.0.0.1",
        "server_port": 1080,
        "password": "8JCsPssfgS8tiRwiMlhARg==",
        "network": "tcp",
        "tls": {},
        "multiplex": {},
        "transport": {},

        ... // Dial Fields
    }
    ```
    """

    type: Literal["trojan"] = "trojan"

    @classmethod
    def from_uniproxy(cls, protocol: TrojanProtocol, **kwargs) -> TrojanOutbound:
        return cls(
            tag=protocol.name,
            server=protocol.server,
            server_port=protocol.port,
            password=protocol.password,
            # network=None if protocol.network == "tcp_and_udp" else protocol.network,
            tls=(
                None
                if protocol.tls is None
                else OutboundTLS.from_uniproxy(protocol.tls)
            ),
            **kwargs,
        )


@define
class Peer:
    allowed_ips: Sequence[IPAddress]
    """WireGuard allowed IPs."""

    server: ServerAddress | None = None
    """The server address. Required if multi-peer disabled"""
    server_port: int | None = None
    """The server port. Required if multi-peer disabled"""
    peer_public_key: str | None = None
    """
    Required if multi-peer disabled

    WireGuard peer public key."""
    pre_shared_key: str | None = None
    """WireGuard pre-shared key."""

    reserved: Sequence[int] | None = None
    """
    WireGuard reserved field bytes.

    $outbound.reserved will be used if empty.
    """


@define(slots=False)
class WireguardMixin:
    local_address: Sequence[IPAddress]
    """
    **Required**

    List of IP (v4 or v6) address prefixes to be assigned to the interface.
    """
    private_key: str
    """
    **Required**

    WireGuard requires base64-encoded public and private keys.
    These can be generated using the wg(8) utility:

    ```
    wg genkey
    echo "private key" || wg pubkey
    ```
    """

    server: ServerAddress | None = None
    """The server address. Required if multi-peer disabled."""
    server_port: int | None = None
    """The server port. Required if multi-peer disabled."""
    peer_public_key: str | None = None
    """Required if multi-peer disabled. WireGuard peer public key."""

    pre_shared_key: str | None = None
    """WireGuard pre-shared key."""

    peers: Sequence[Peer] | None = None
    """
    Multi-peer support.

    If enabled, `server`, `server_port`, `peer_public_key`, `pre_shared_key` will be ignored.
    """

    reserved: Sequence[int] | None = None
    """WireGuard reserved field bytes."""

    system_interface: str | None = None
    """
    Use system interface.

    Requires privilege and cannot conflict with exists system interfaces.

    Forced if gVisor not included in the build.
    """
    interface_name: str | None = None
    """Custom interface name for system interface."""
    gso: bool | None = None
    """Try to enable generic segmentation offload."""
    workers: int | None = None
    """WireGuard worker count. CPU count is used by default."""
    mtu: int | None = None
    """WireGuard MTU. 1408 will be used if empty."""
    network: SingBoxNetwork | None = None
    """Enabled network. One of tcp udp. Both is enabled by default."""


@define
class WireguardOutbound(DialFieldsMixin, WireguardMixin, BaseOutbound):  # type: ignore[misc]
    """
    Examples:

    ```json
    {
    "type": "wireguard",
    "tag": "wireguard-out",

    "server": "127.0.0.1",
    "server_port": 1080,
    "system_interface": false,
    "gso": false,
    "interface_name": "wg0",
    "local_address": [
        "10.0.0.2/32"
    ],
    "private_key": "YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04=",
    "peers": [
        {
        "server": "127.0.0.1",
        "server_port": 1080,
        "public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=",
        "pre_shared_key": "31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM=",
        "allowed_ips": [
            "0.0.0.0/0"
        ],
        "reserved": [0, 0, 0]
        }
    ],
    "peer_public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=",
    "pre_shared_key": "31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM=",
    "reserved": [0, 0, 0],
    "workers": 4,
    "mtu": 1408,
    "network": "tcp",

    ... // Dial Fields
    }
    ```
    """

    type: Literal["wireguard"] = "wireguard"


@define
class SelectorOutbound(BaseOutbound):
    """

    Examples:

    ```json
    {
        "type": "selector",
        "tag": "select",

        "outbounds": [
            "proxy-a",
            "proxy-b",
            "proxy-c"
        ],
        "default": "proxy-c",
        "interrupt_exist_connections": false
    }
    ```
    """

    outbounds: Sequence[SingBoxOutbound | str] = field(converter=map_to_str)
    default: SingBoxOutbound | str | None = None
    interrupt_exist_connections: bool | None = None
    type: Literal["selector"] = "selector"

    @classmethod
    def from_uniproxy(cls, protocol: SelectGroup, **kwargs) -> SelectorOutbound:
        return cls(
            tag=protocol.name,
            outbounds=[str(i) for i in protocol.proxies] if protocol.proxies else [],
            interrupt_exist_connections=False,
        )


@define
class UrlTestOutbound(BaseOutbound):
    """
    Examples:

    ```json
    {
      "type": "urltest",
      "tag": "auto",

      "outbounds": [
        "proxy-a",
        "proxy-b",
        "proxy-c"
      ],
      "url": "",
      "interval": "",
      "tolerance": 0,
      "idle_timeout": "",
      "interrupt_exist_connections": false
    }
    ```
    """

    outbounds: Sequence[SingBoxOutbound | str] = field(converter=map_to_str)
    """List of outbound tags to test."""
    url: str | None = None
    """The URL to test. `https://www.gstatic.com/generate_204` will be used if empty."""
    interval: str | None = None
    """The test interval. `3m` will be used if empty."""
    tolerance: float | None = None
    """The test tolerance in milliseconds. `50` will be used if empty."""
    idle_timeout: str | None = None
    """The idle timeout. 30m will be used if empty."""
    interrupt_exist_connections: bool | None = None
    """
    Interrupt existing connections when the selected outbound has changed.

    Only outbound connections are affected by this setting, internal connections will always be interrupted.
    """

    domain_resolver: str | BaseDnsServer | None = field(
        default=None, converter=lambda x: str(x) if x is not None else None
    )

    type: Literal["urltest"] = "urltest"

    @classmethod
    def from_uniproxy(cls, protocol: UrlTestGroup, **kwargs) -> UrlTestOutbound:
        return cls(
            tag=protocol.name,
            outbounds=[str(i) for i in protocol.proxies] if protocol.proxies else [],
            url=protocol.url,
            interval=f"{protocol.interval}s" if protocol.interval else None,
            tolerance=protocol.tolerance,
        )


@define
class PseudoLoadBalanceOutbound(BaseOutbound):
    outbounds: Sequence[SingBoxOutbound | str] = field(converter=map_to_str)
    url: str | None = None
    interval: str | None = None
    tolerance: float | None = None
    idle_timeout: str | None = None
    interrupt_exist_connections: bool | None = None
    type: Literal["urltest"] = "urltest"

    @classmethod
    def from_uniproxy(cls, protocol: LoadBalanceGroup, **kwargs) -> UrlTestOutbound:
        return cls(  # type: ignore
            tag=protocol.name,
            outbounds=[str(i) for i in protocol.proxies] if protocol.proxies else [],
            url=protocol.url,
            interval=f"{protocol.interval}s" if protocol.interval else None,
            tolerance=100,
        )


@define
class PseudoFallbackOutbound(BaseOutbound):
    outbounds: Sequence[SingBoxOutbound | str] = field(converter=map_to_str)
    default: SingBoxOutbound | str | None = None
    interrupt_exist_connections: bool | None = None
    type: Literal["selector"] = "selector"

    @classmethod
    def from_uniproxy(cls, protocol: SelectGroup, **kwargs) -> SelectorOutbound:
        return cls(  # type: ignore
            tag=protocol.name,
            outbounds=[str(i) for i in protocol.proxies] if protocol.proxies else [],
            interrupt_exist_connections=False,
        )


SingBoxProtocolOutbound = (
    DirectOutbound
    | ShadowsocksOutbound
    | VmessOutbound
    | TrojanOutbound
    | WireguardOutbound
)
SingBoxGroupOutbound = SelectorOutbound | UrlTestOutbound
SingBoxOutbound = SingBoxProtocolOutbound | SingBoxGroupOutbound


_SINGBOX_REGISTERED_PROTOCOLS: Mapping[ProtocolType, SingBoxProtocolOutbound] = {  # type: ignore[reportAssignmentType]
    # "direct": DirectOutbound,
    # "block": BlockOutbound,
    # "dns": DnsOutbound,
    "shadowsocks": ShadowsocksOutbound,
    "vmess": VmessOutbound,
    "trojan": TrojanOutbound,
    "wireguard": WireguardOutbound,
}
_SINGBOX_REGISTERED_PROXY_GROUPS: Mapping[GroupType, SingBoxGroupOutbound] = {  # type: ignore[reportAssignmentType]
    "select": SelectorOutbound,
    "url-test": UrlTestOutbound,
    "load-balance": PseudoLoadBalanceOutbound,
    "fallback": PseudoFallbackOutbound,
}


def is_valid_protocol(proxy: Any) -> TypeGuard[UniproxyProtocol]:
    """
    Check if the protocol type is valid for SingBox.
    """

    return hasattr(proxy, "type") or proxy.type in _SINGBOX_REGISTERED_PROTOCOLS.keys()


def is_valid_protocol_group(proxy: Any) -> TypeGuard[UniproxyProxyGroup]:
    """
    Check if the protocol type is valid for SingBox.
    """

    return (
        hasattr(proxy, "type") or proxy.type in _SINGBOX_REGISTERED_PROXY_GROUPS.keys()
    )


def make_protocol_outbound_from_uniproxy(
    protocol: UniproxyProtocol, **kwargs
) -> SingBoxProtocolOutbound:
    if is_valid_protocol(protocol):
        # FIXME: type violation
        return _SINGBOX_REGISTERED_PROTOCOLS[protocol.type].from_uniproxy(
            protocol,  # type: ignore
            **kwargs,
        )
    else:
        raise ValueError(
            f"Unsupported or not implemented protocol type {protocol.type}"
        )


def make_group_outbound_from_uniproxy(
    protocol: UniproxyProxyGroup, **kwargs
) -> SingBoxOutbound:
    if protocol.type in _SINGBOX_REGISTERED_PROXY_GROUPS.keys():
        return _SINGBOX_REGISTERED_PROXY_GROUPS[protocol.type].from_uniproxy(
            protocol,  # type: ignore
            **kwargs,
        )
    else:
        raise ValueError(
            f"Unsupported or not implemented protocol type {protocol.type}"
        )


def make_outbound_from_uniproxy(
    protocol: UniproxyProtocol | UniproxyProxyGroup, **kwargs
) -> SingBoxOutbound:
    if is_valid_protocol(protocol):
        return make_protocol_outbound_from_uniproxy(protocol, **kwargs)
    elif is_valid_protocol_group(protocol):
        return make_group_outbound_from_uniproxy(protocol, **kwargs)
    else:
        raise ValueError(
            f"Unsupported or not implemented protocol type {protocol.type}"
        )
