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
    HttpProtocol,
    ShadowsocksObfsPlugin,
    ShadowsocksProtocol,
    TrojanProtocol,
    UniproxyProtocol,
    VmessProtocol,
)
from uniproxy.proxy_groups import SelectGroup, UniproxyProxyGroup, UrlTestGroup
from uniproxy.utils import map_to_str

from .base import BaseOutbound
from .shared import (
    BaseTransport,
    DialFieldsMixin,
    OutboundMultiplex,
    OutboundTLS,
    UdpOverTcp,
)
from .typing import SingBoxNetwork

__all__ = (
    "DirectOutbound",
    "ShadowsocksOutbound",
    "VmessOutbound",
    "TrojanOutbound",
    "NaiveOutbound",
    "AnyTLSOutbound",
    "UrlTestOutbound",
    "SelectorOutbound",
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
class DirectOutbound(DialFieldsMixin, DirectMixin, BaseOutbound):
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
class HttpMixin:
    server: ServerAddress
    """The server address."""
    server_port: int
    """The server port."""
    username: str | None = None
    """Basic authorization username."""
    password: str | None = None
    """Basic authorization password."""
    path: str | None = None
    """Path of HTTP request."""
    headers: Mapping[str, str] | None = None
    """Extra headers of HTTP request."""
    tls: OutboundTLS | None = None


@define
class HttpOutbound(DialFieldsMixin, HttpMixin, BaseOutbound):
    """
    Examples:

    ```json
    {
      "type": "http",
      "tag": "http-out",

      "server": "127.0.0.1",
      "server_port": 1080,
      "username": "sekai",
      "password": "admin",
      "path": "",
      "headers": {},
      "tls": {},

      ... // Dial Fields
    }
    ```
    """

    type: Literal["http"] = "http"

    @classmethod
    def from_uniproxy(cls, protocol: HttpProtocol, **kwargs) -> HttpOutbound:

        if protocol.type == "https":
            if protocol.tls is None:
                tls = OutboundTLS(enabled=True)
            else:
                tls = OutboundTLS.from_uniproxy(protocol.tls)
        else:
            tls = None

        return cls(
            tag=protocol.name,
            server=protocol.server,
            server_port=protocol.port,
            username=protocol.username,
            password=protocol.password,
            tls=tls,
            **kwargs,
        )


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
    udp_over_tcp: Literal[False] | UdpOverTcp | None = None
    """UDP over TCP configuration. Conflict with `multiplex`."""
    multiplex: OutboundMultiplex | None = None
    """See Multiplex for details."""

    def __attrs_post_init__(self):
        if self.udp_over_tcp and self.multiplex:
            raise ValueError(
                "Option 'udp_over_tcp' and 'multiplex' cannot be used together"
            )


@define
class ShadowsocksOutbound(DialFieldsMixin, ShadowsocksMixin, BaseOutbound):
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
class VmessOutbound(DialFieldsMixin, VmessMixin, BaseOutbound):
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
class TrojanOutbound(DialFieldsMixin, TrojanMixin, BaseOutbound):
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


@define(slots=False)
class NaiveMixin:
    server: ServerAddress
    """The server address."""
    server_port: int
    """The server port."""
    tls: OutboundTLS
    """TLS configuration, see [[TLS]]."""

    username: str | None = None
    """Authentication username."""
    password: str | None = None
    """Authentication password."""

    insecure_concurrency: bool | None = None
    """
    Number of concurrent tunnel connections. Multiple connections make the
    tunneling easier to detect through traffic analysis, which defeats the
    purpose of NaiveProxy's design to resist traffic analysis."""
    extra_headers: dict | None = None
    """Extra headers to send in HTTP requests."""
    udp_over_tcp: Literal[False] | UdpOverTcp | None = None
    """UDP over TCP protocol settings. See [[UDP Over TCP]] for details."""
    quic: bool | None = None
    """Use QUIC instead of HTTP/2."""
    quic_congestion_control: str | None = None
    """
    QUIC congestion control algorithm.

    | Algorithm | Description |
    | --------- | ----------- |
    | `bbr`     | BBR         |
    | `bbr2`    | BBRv2       |
    | `cubic`   | CUBIC       |
    | `reno`    | New Reno    |

    `bbr` is used by default (the default of QUICHE, used by Chromium which NaiveProxy is based on).
    """


@define
class NaiveOutbound(DialFieldsMixin, NaiveMixin, BaseOutbound):
    """
    Since sing-box 1.13.0

    Examples:

    ```json
    "type": "naive",
    "tag": "naive-out",

    "server": "127.0.0.1",
    "server_port": 443,
    "username": "sekai",
    "password": "password",
    "insecure_concurrency": 0,
    "extra_headers": {},
    "udp_over_tcp": false | {},
    "quic": false,
    "quic_congestion_control": "",
    "tls": {},

    ... // Dial Fields
    ```
    """

    type: Literal["naive"] = "naive"


@define(slots=False)
class AnyTLSMixin:
    server: ServerAddress
    """The server address."""
    server_port: int
    """The server port."""
    password: str
    """The AnyTLS password."""
    tls: OutboundTLS
    """TLS configuration, see [[TLS]]."""
    idle_session_check_interval: str | None = None
    """Interval checking for idle sessions. Default: `30s`."""
    idle_session_timeout: str | None = None
    """In the check, close sessions that have been idle for longer than this. Default: `30s`."""
    min_idle_session: int | None = None
    """In the check, at least the first `n` idle sessions are kept open. Default value: `n=0`."""


@define
class AnyTLSOutbound(DialFieldsMixin, AnyTLSMixin, BaseOutbound):
    """
    Since sing-box 1.12.0

    Examples:

    ```json
    "type": "anytls",
    "tag": "anytls-out",

    "server": "127.0.0.1",
    "server_port": 1080,
    "password": "8JCsPssfgS8tiRwiMlhARg==",
    "idle_session_check_interval": "30s",
    "idle_session_timeout": "30s",
    "min_idle_session": 5,
    "tls": {},

    ... // Dial Fields
    ```
    """

    type: Literal["anytls"] = "anytls"


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

    # domain_resolver: str | BaseDnsServer | None = field(
    #     default=None, converter=lambda x: str(x) if x is not None else None
    # )

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


SingBoxProtocolOutbound = (
    DirectOutbound | ShadowsocksOutbound | VmessOutbound | TrojanOutbound
)
SingBoxGroupOutbound = SelectorOutbound | UrlTestOutbound
SingBoxOutbound = SingBoxProtocolOutbound | SingBoxGroupOutbound


_SINGBOX_REGISTERED_PROTOCOLS: Mapping[ProtocolType, SingBoxProtocolOutbound] = {  # type: ignore[reportAssignmentType]
    # "direct": DirectOutbound,
    # "block": BlockOutbound,
    # "dns": DnsOutbound,
    "http": HttpOutbound,
    "https": HttpOutbound,
    "shadowsocks": ShadowsocksOutbound,
    "vmess": VmessOutbound,
    "trojan": TrojanOutbound,
    "anytls": AnyTLSOutbound,
    "naive": NaiveOutbound,
}
_SINGBOX_REGISTERED_PROXY_GROUPS: Mapping[GroupType, SingBoxGroupOutbound] = {  # type: ignore[reportAssignmentType]
    "select": SelectorOutbound,
    "url-test": UrlTestOutbound,
}


def is_valid_protocol(proxy: Any) -> TypeGuard[UniproxyProtocol]:
    """
    Check if the protocol type is valid for SingBox.
    """

    return hasattr(proxy, "type") and proxy.type in _SINGBOX_REGISTERED_PROTOCOLS.keys()


def is_valid_protocol_group(proxy: Any) -> TypeGuard[UniproxyProxyGroup]:
    """
    Check if the protocol type is valid for SingBox.
    """

    return (
        hasattr(proxy, "type") and proxy.type in _SINGBOX_REGISTERED_PROXY_GROUPS.keys()
    )


def _make_protocol_outbound_from_uniproxy(
    protocol: UniproxyProtocol, **kwargs
) -> SingBoxProtocolOutbound:
    if is_valid_protocol(protocol):
        # FIXME: type violation
        return _SINGBOX_REGISTERED_PROTOCOLS[protocol.type].from_uniproxy(
            protocol, **kwargs
        )
    else:
        raise ValueError(
            f"Unsupported or not implemented protocol type {protocol.type}"
        )


def _make_group_outbound_from_uniproxy(
    protocol: UniproxyProxyGroup, **kwargs
) -> SingBoxOutbound:
    if protocol.type in _SINGBOX_REGISTERED_PROXY_GROUPS.keys():
        return _SINGBOX_REGISTERED_PROXY_GROUPS[protocol.type].from_uniproxy(
            protocol, **kwargs
        )
    else:
        raise ValueError(
            f"Unsupported or not implemented protocol type {protocol.type}"
        )


def make_outbound_from_uniproxy(
    protocol: UniproxyProtocol | UniproxyProxyGroup, **kwargs
) -> SingBoxOutbound:
    if is_valid_protocol(protocol):
        return _make_protocol_outbound_from_uniproxy(protocol, **kwargs)
    elif is_valid_protocol_group(protocol):
        return _make_group_outbound_from_uniproxy(protocol, **kwargs)
    else:
        raise ValueError(
            f"Unsupported or not implemented protocol type {protocol.type}"
        )
