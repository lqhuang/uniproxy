from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import IPAddress, ServerAddress, ShadowsocksCipher, VmessCipher

from attrs import define, field

from uniproxy.protocols import ShadowsocksProtocol, VmessProtocol
from uniproxy.utils import map_to_str

from .base import BaseOutbound
from .shared import BaseTransport, DialFieldsMixin, OutboundMultiplex, OutboundTLS
from .typing import SingBoxNetwork

PROTOCOL_OUTBOUNDS = {
    "direct",
    "block",
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "trojan",
    "wireguard",
    "hysteria",
    "shadowtls",
    "vless",
    "tuic",
    "hysteria2",
    "tor",
    "ssh",
    "dns",
}
GROUP_OUTBOUNDS = {"selector", "urltest"}


@define(slots=False)
class SingBoxOutbound(BaseOutbound): ...


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

    type: Literal["direct"] = "direct"


@define
class DirectOutbound(DialFieldsMixin, DirectMixin, SingBoxOutbound):
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


@define
class BlockOutbound(SingBoxOutbound):
    """

    Examples:

    ```json
    {
      "type": "block",
      "tag": "block"
    }
    ```
    """

    type: Literal["block"] = "block"


@define
class DnsOutbound(SingBoxOutbound):
    """

    Examples:

    ```json
    {
        "type": "dns",
        "tag": "dns-out"
        ...
    ```
    """

    tag: str
    type: Literal["dns"] = "dns"


@define(slots=False)
class ShadowsocksMixin:
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
    # dial: DialFields | None = None
    # """See Dial Fields for details."""

    type: Literal["shadowsocks"] = "shadowsocks"

    def __attrs_post_init__(self):
        if self.udp_over_tcp and self.multiplex:
            raise ValueError(
                "Option 'udp_over_tcp' and 'multiplex' cannot be used together"
            )


@define
class ShadowsocksOutbound(DialFieldsMixin, ShadowsocksMixin, SingBoxOutbound):
    @classmethod
    def from_uniproxy(cls, ss: ShadowsocksProtocol, **kwargs) -> ShadowsocksOutbound:
        return cls(
            tag=ss.name,
            server=ss.server,
            server_port=ss.port,
            method=ss.method,
            password=ss.password,
            network=None if ss.network == "tcp_and_udp" else ss.network,
            plugin=ss.plugin.command if ss.plugin else None,
            plugin_opts=ss.plugin.opts if ss.plugin else None,
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
    type: Literal["vmess"] = "vmess"


@define
class VmessOutbound(DialFieldsMixin, VmessMixin, SingBoxOutbound):

    @classmethod
    def from_uniproxy(cls, vmess: VmessProtocol, **kwargs) -> VmessOutbound:
        transport_mapping = {
            # "ws": "ws",
            # "h2": "h2",
            # "quic": "quic",
            "httpupgrade": NotImplementedError("httpupgrade"),
        }
        if vmess.transport is not None:
            # transport = transport_mapping[vmess.transport]
            raise NotImplementedError("unsupported transport type for now")

        return cls(
            tag=vmess.name,
            server=vmess.server,
            server_port=vmess.port,
            uuid=vmess.uuid,
            security=vmess.security,
            alter_id=vmess.alter_id,
            network=None if vmess.network == "tcp_and_udp" else vmess.network,
            tls=None if vmess.tls is None else OutboundTLS.from_uniproxy(vmess.tls),
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
    # dial: DialFields | None = None
    """See Dial Fields for details."""

    type: Literal["trojan"] = "trojan"


@define
class TrojanOutbound(DialFieldsMixin, TrojanMixin, SingBoxOutbound):
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
    """
    Required if multi-peer disabled. WireGuard peer public key."""

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
    type: Literal["wireguard"] = "wireguard"


@define
class WireguardOutbound(DialFieldsMixin, WireguardMixin, SingBoxOutbound):
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


@define
class SelectorOutbound(SingBoxOutbound):
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

    outbounds: Sequence[BaseOutbound | str] = field(converter=map_to_str)
    default: BaseOutbound | str | None = None
    interrupt_exist_connections: bool | None = None
    type: Literal["selector"] = "selector"


@define
class URLTestOutbound(SingBoxOutbound):
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

    outbounds: Sequence[BaseOutbound | str] = field(converter=map_to_str)
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

    Only inbound connections are affected by this setting, internal connections will always be interrupted.
    """

    type: Literal["urltest"] = "urltest"


# TODO: bug??
# ...
# Not a bug
# https://www.attrs.org/en/stable/glossary.html#term-slotted-classes
# https://github.com/python-attrs/attrs/issues/407
# import gc
#
# gc.collect()
#
# _SINGBOX_REGISTERED_OUTBOUNDS = {
#     key: subcls
#     for subcls in SingBoxOutbound.__subclasses__()
#     if isinstance(key := getattr(subcls, "type"), str)
# }
# for subclss in SingBoxOutbound.__subclasses__():
#     print(subclss, subclss.type.__name__)
#     print(dir(subclss.type))

_SINGBOX_REGISTERED_OUTBOUNDS = {
    "direct": DirectOutbound,
    "block": BlockOutbound,
    "dns": DnsOutbound,
    "shadowsocks": ShadowsocksOutbound,
    "vmess": VmessOutbound,
    "wireguard": WireguardOutbound,
    "trojan": TrojanOutbound,
    "selector": SelectorOutbound,
    "urltest": URLTestOutbound,
}
