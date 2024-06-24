from __future__ import annotations

from typing import Literal

from ipaddress import IPv4Address, IPv6Address

from attrs import frozen

from uniproxy.protocols import VmessProtocol, ShadowsocksProtocol
from uniproxy.typing import VmessCipher, ShadowsocksCipher

from .base import BaseOutbound
from .shared import BaseTransport, OutboundMultiplex, OutboundTLS
from .typing import SingBoxNetwork


@frozen
class DirectOutbound(BaseOutbound):
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

    # Override the connection destination address.
    override_address: IPv4Address | IPv6Address | str | None = None
    # Override the connection destination port.
    override_port: int | None = None
    # Write [Proxy Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) in the connection header.
    #
    # Protocol value can be `1` or `2`.
    proxy_protocol: Literal[1, 2] | None = None


@frozen
class ShadowsocksOutbound(BaseOutbound):
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

    # The server address.
    server: IPv4Address | IPv6Address | str
    # The server port.
    server_port: int
    # Encryption methods.
    method: ShadowsocksCipher
    # The shadowsocks password.
    password: str
    # Shadowsocks SIP003 plugin, implemented in internal.
    plugin: Literal["obfs-local", "v2ray-plugin"] | str | None = None
    # Shadowsocks SIP003 plugin options.
    plugin_opts: str | None = None
    # Enabled network. One of `tcp`, `udp`.
    # Both is enabled by default.
    network: SingBoxNetwork | None = None
    # UDP over TCP configuration. Conflict with `multiplex`.
    udp_over_tcp: bool | dict | None = False
    # See Multiplex for details.
    multiplex: OutboundMultiplex | None = None
    # # See Dial Fields for details.
    # dial: DialFields | None = None
    type: Literal["shadowsocks"] = "shadowsocks"

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


@frozen
class VmessOutbound(BaseOutbound):

    tag: str
    server: IPv4Address | IPv6Address | str | None
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


@frozen
class DnsOutbound(BaseOutbound):
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
    type: Literal["dns"]


@frozen
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

    tag: str
    outbounds: list[BaseOutbound] | list[str]
    default: BaseOutbound | str | None = None
    interrupt_exist_connections: bool | None = None
    type: Literal["selector"] = "selector"
