from __future__ import annotations

from typing import Any, Literal, Mapping, Sequence, cast
from uniproxy.typing import (
    AlpnType,
    IPAddress,
    IPv4Address,
    IPv6Address,
    ProtocolType,
    ShadowsocksCipher,
    VmessCipher,
    VmessTransportType,
)

from attrs import define, field
from xattrs._metadata import _Metadata

from uniproxy.protocols import HttpProtocol as UniproxyHttpProtocol
from uniproxy.protocols import ShadowsocksObfsPlugin as UniproxyShadowsocksObfsPlugin
from uniproxy.protocols import ShadowsocksProtocol as UniproxyShadowsocksProtocol
from uniproxy.protocols import ShadowsocksV2RayPlugin as UniproxyShadowsocksV2RayPlugin
from uniproxy.protocols import TrojanProtocol as UniproxyTrojanProtocol
from uniproxy.protocols import UniproxyProtocol
from uniproxy.protocols import VmessH2Transport as UniproxyVmessH2Transport
from uniproxy.protocols import VmessProtocol as UniproxyVmessProtocol
from uniproxy.protocols import VmessWsTransport as UniproxyVmessWsTransport
from uniproxy.protocols import WireGuardPeer as UniproxyWireguardPeer
from uniproxy.protocols import WireGuardProtocol as UniproxyWireguardProtocol

from .base import BaseProtocol

# @define
# class ClashProtocol(BaseProtocol):
#     @classmethod
#     def from_uniproxy(cls, protocol, **kwargs) -> ClashProtocol:
#         raise NotImplementedError

#     def to_uniproxy(self, **kwargs) -> UniproxyProtocol:
#         return self.to_uniproxy()


@define
class HttpProtocol(BaseProtocol):
    username: str | None = None
    password: str | None = None
    tls: bool | None = field(default=None)
    skip_cert_verify: bool | None = None
    headers: dict[str, str] | None = None

    type: Literal["http", "https"] = "http"

    @tls.validator  # type: ignore[reportAttributeAccessIssue]
    def _may_conflict_with_https(self, attribute, value):
        if self.type == "https" and value is False:
            raise ValueError("'tls' option for https protocol cannot be False")

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyHttpProtocol, **kwargs) -> HttpProtocol:
        if protocol.tls is not None:
            skip_cert_verify = not protocol.tls.verify
        else:
            skip_cert_verify = None

        return cls(
            protocol.name,
            protocol.server,
            protocol.port,
            username=protocol.username,
            password=protocol.password,
            tls=True if protocol.tls is not None else protocol.tls,
            skip_cert_verify=skip_cert_verify,
            type="https" if protocol.tls is not None else "http",
        )


@define
class Socks5Protocol(BaseProtocol):
    username: str | None = None
    password: str | None = None
    udp: bool = True
    tls: bool | None = field(default=None)
    skip_cert_verify: bool | None = None

    type: Literal["socks5", "socks5-tls"] = "socks5"

    @tls.validator  # type: ignore[reportAttributeAccessIssue]
    def _may_conflict_with_socks5_tls(self, attribute, value):
        if self.type == "socks5-tls" and value is False:
            raise ValueError("'tls' option for 'socks5-tls' protocol cannot be False")


@define
class ShadowsocksPluginObfsOpts:
    mode: Literal["tls", "http"]
    host: str


@define
class ShadowsocksPluginV2RayOpts:
    mode: Literal["websocket"]
    host: str
    path: str
    tls: bool | None = None
    skip_cert_verify: bool | None = None
    headers: dict[str, str] | None = None


@define
class ShadowsocksProtocol(BaseProtocol):
    """
    YAML example:

    ```yaml
    name: "proxy-name"
    type: "ss"
    server: host
    port: 8842
    cipher: "aes-256-gcm"
    password: "x-secret-token"
    udp: true
    ```
    """

    cipher: ShadowsocksCipher
    password: str
    udp: bool | None = None
    plugin: Literal["obfs", "v2ray-plugin"] | None = field(default=None)
    plugin_opts: ShadowsocksPluginObfsOpts | ShadowsocksPluginV2RayOpts | None = None

    type: Literal["ss"] = "ss"

    @plugin.validator  # type: ignore[reportAttributeAccessIssue]
    def _may_conflict_with_plugin_opts(self, attribute, value):
        if value is None and self.plugin_opts is not None:
            raise ValueError(
                f"'plugin_opts' must be None when 'plugin' is not set, got {self.plugin_opts}"
            )

    @classmethod
    def from_uniproxy(
        cls, protocol: UniproxyShadowsocksProtocol, **kwargs
    ) -> ShadowsocksProtocol:
        plugin = protocol.plugin.command if protocol.plugin else None

        plugin_opts: ShadowsocksPluginObfsOpts | ShadowsocksPluginV2RayOpts | None
        match plugin:
            case "obfs-local" | "obfs":
                plug = cast(UniproxyShadowsocksObfsPlugin, protocol.plugin)
                plugin_opts = ShadowsocksPluginObfsOpts(
                    mode=plug.obfs, host=plug.obfs_host
                )
            case "v2ray-plugin":
                plug_ = cast(UniproxyShadowsocksV2RayPlugin, protocol.plugin)
                if plug_.mode != "websocket":
                    raise NotImplementedError(f"Unknown mode: {plug_.mode}")
                plugin_opts = ShadowsocksPluginV2RayOpts(
                    mode=plug_.mode,  # type: ignore[arg-type]
                    host=plug_.host,
                    path=plug_.path,
                    tls=plug_.tls,
                    skip_cert_verify=plug_.skip_cert_verify,
                    headers=plug_.headers,
                )
            case None:
                plugin_opts = None
            case _:
                raise NotImplementedError(f"Unknown plugin: {plugin}")

        return cls(
            protocol.name,
            protocol.server,
            protocol.port,
            cipher=protocol.method,
            password=protocol.password,
            udp=protocol.network != "tcp",
            plugin="obfs" if plugin == "obfs-local" else plugin,
            plugin_opts=plugin_opts,
        )


@define
class TrojanProtocol(BaseProtocol):
    """
    ```yaml
    name: trojan
    type: trojan
    server: server
    port: 443
    password: yourpassword
    # udp: true
    # sni: example.com # Server Name Indication, value of `server` will be used if not set
    # alpn:
    #   - h2
    #   - http/1.1
    # skip-cert-verify: true
    ```
    """

    password: str
    sni: str | None = None
    skip_cert_verify: bool | None = None
    alpn: Sequence[AlpnType] | None = None

    udp: bool | None = None

    type: Literal["trojan"] = "trojan"

    @classmethod
    def from_uniproxy(
        cls, protocol: UniproxyTrojanProtocol, **kwargs
    ) -> TrojanProtocol:
        if protocol.tls is not None:
            skip_cert_verify = not protocol.tls.verify
            sni = protocol.tls.server_name
            alpn = protocol.tls.alpn
        else:
            skip_cert_verify = None
            sni = None
            alpn = None

        return cls(
            protocol.name,
            protocol.server,
            protocol.port,
            password=protocol.password,
            sni=sni,
            skip_cert_verify=skip_cert_verify,
            alpn=alpn,
            udp=protocol.network != "tcp",
        )


@define
class VmessWsTransport:
    """
    YAML example:

    ```yaml
    network: ws
    ws-opts:
      path: /path
      headers:
          Host: v2ray.com
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
    ```
    """

    path: str | None
    headers: dict[str, str] | None = None
    max_early_data: int | None = None
    early_data_header_name: str | None = None


@define
class VmessH2Transport:
    """
    YAML example:

    ```yaml
    h2-opts:
      path: /path
      headers:
      Host: v2ray.com
    ```
    """

    path: str | None
    headers: dict[str, str] | None = None


@define
class VmessProtocol(BaseProtocol):
    """

    YAML example:

    ```yaml
    name: vmess-proxy-xxx
    type: vmess
    server: host
    port: 2142
    uuid: uuid-string
    alterId: 0
    cipher: auto
    tls: true
    skip-cert-verify: true
    udp: true
    servername: some-host-name
    network: ws
    ```
    """

    uuid: str
    alter_id: int = field(default=0) | _Metadata(name="alterId")  # type: ignore[assignment,operator]
    cipher: VmessCipher = "auto"
    udp: bool | None = None
    tls: bool | None = None
    skip_cert_verify: bool | None = None
    servername: str | None = None
    """
    overwrite the server name defined in 'ws-opts'/'h2-opts'
    """

    network: VmessTransportType | None = None
    ws_opts: VmessWsTransport | None = None
    h2_opts: VmessH2Transport | None = None

    type: Literal["vmess"] = "vmess"

    def __attrs_post_init__(self):
        if self.ws_opts is not None and self.h2_opts is not None:
            raise ValueError("Only one of 'ws_opts' and 'h2_opts' can be set")
        if self.network == "ws" and self.h2_opts is not None:
            raise ValueError("'h2_opts' is set but network is 'ws'")
        if self.network == "h2" and self.ws_opts is not None:
            raise ValueError("'ws_opts' is set but network is 'h2'")

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyVmessProtocol, **kwargs) -> VmessProtocol:
        if protocol.tls is not None:
            skip_cert_verify = not protocol.tls.verify
            servername = protocol.tls.server_name
        else:
            skip_cert_verify = None
            servername = None

        if (transport := protocol.transport) is not None:
            transport_network = transport.type
            match transport_network:
                case "ws":
                    ws_transport = cast(UniproxyVmessWsTransport, transport)
                    ws_opts = VmessWsTransport(
                        path=ws_transport.path,
                        headers=ws_transport.headers,
                        max_early_data=ws_transport.max_early_data,
                        early_data_header_name=ws_transport.early_data_header_name,
                    )
                    h2_opts = None
                case "h2":
                    h2_transport = cast(UniproxyVmessH2Transport, transport)
                    ws_opts = None  # type: ignore[assignment]
                    h2_opts = VmessH2Transport(
                        path=h2_transport.path, headers=h2_transport.headers
                    )
                case _:
                    raise NotImplementedError(
                        f"Unknown transport type: {transport_network}"
                    )
        else:
            transport_network = None
            ws_opts = None
            h2_opts = None

        return cls(
            protocol.name,
            protocol.server,
            protocol.port,
            uuid=protocol.uuid,
            alter_id=protocol.alter_id,
            cipher=protocol.security,
            tls=True if protocol.tls is not None else protocol.tls,
            skip_cert_verify=skip_cert_verify,
            udp=protocol.network != "tcp",
            servername=servername,
            network=transport_network,
            ws_opts=ws_opts,
            h2_opts=h2_opts,
        )


@define
class WireguardProtocol(BaseProtocol):
    """
    YAML example:

    ```yaml
    name: wireguard
    type: wireguard
    server: server # domain is supported
    port: 51820
    ip: 10.8.4.8
    # ipv6: fe80::e6bf:faff:fea0:9fae # optional
    private-key: 0G6TTWwvgv8Gy5013/jv2GttkCLYYaNTArHV0NdNkGI= # client private key
    public-key: 0ag+C+rINHBnvLJLUyJeYkMWvIAkBjQPPObicuBUn1U= # peer public key
    # preshared-key: # optional
    dns: [1.0.0.1, 223.6.6.6] # optional
    # mtu: 1420 # optional
    # reserved: [0, 0, 0] # optional
    # keepalive: 45 # optional
    # underlying-proxy: # optional
    #   type: trojan
    #   server: your-underlying-proxy
    #   port: 443
    #   password: your-password
    ```
    """

    private_key: str
    public_key: str

    ip: str | IPv4Address | None = None
    ipv6: str | IPv6Address | None = None

    dns: Sequence[IPAddress] | None = None

    # stash style now ..... in mihomo, it is called `pre-shared-key`
    preshared_key: str | None = None

    ## field not existed for stash
    # allowed_ips: Sequence[NetworkCIDR | str] = ["0.0.0.0/0", "::/0"]
    ## field not existed for mihomo
    # keepalive: int | None = None

    type: Literal["wireguard"] = "wireguard"

    def __attrs_post_init__(self):
        if self.ip is None and self.ipv6 is None:
            raise ValueError("Either 'ip' or 'ipv6' must be set")
        if self.ip is not None and self.ipv6 is not None:
            raise ValueError("Only one of 'ip' and 'ipv6' can be set")

    @classmethod
    def from_uniproxy(
        cls, protocol: UniproxyWireguardProtocol, **kwargs
    ) -> WireguardProtocol:
        if isinstance(protocol.address, IPv4Address):
            is_ipv6 = False
        elif isinstance(protocol.address, IPv6Address):
            is_ipv6 = True
        elif isinstance(protocol.address, str):
            # If address is a string, it could be an IPv4 or IPv6 address
            if ":" in protocol.address:
                is_ipv6 = True
            else:
                is_ipv6 = False
        else:
            raise ValueError(
                f"Unknown address type: {type(protocol.address)} for WireGuard protocol"
            )

        return cls(
            protocol.name,
            protocol.server,
            protocol.port,
            private_key=protocol.private_key,
            public_key=protocol.peer.public_key,
            ip=protocol.address if not is_ipv6 else None,
            ipv6=cast(IPv6Address | str, protocol.address) if is_ipv6 else None,
            preshared_key=protocol.peer.pre_shared_key,
            type="wireguard",
        )


_CLASH_MAPPER: Mapping[ProtocolType, type[BaseProtocol]] = {
    "http": HttpProtocol,
    "https": HttpProtocol,
    "socks5": Socks5Protocol,
    "socks5-tls": Socks5Protocol,
    "shadowsocks": ShadowsocksProtocol,
    "vmess": VmessProtocol,
    "trojan": TrojanProtocol,
    # "tuic": TuicProtocol,
    "wireguard": WireguardProtocol,
}

ClashProtocol = (
    HttpProtocol
    | Socks5Protocol
    | ShadowsocksProtocol
    | VmessProtocol
    | TrojanProtocol
    | WireguardProtocol
)


def make_protocol_from_uniproxy(
    protocol: UniproxyProtocol | ClashProtocol, **kwargs
) -> ClashProtocol:
    if isinstance(protocol, ClashProtocol):
        return protocol
    elif isinstance(protocol, UniproxyProtocol):
        try:
            return _CLASH_MAPPER[protocol.type].from_uniproxy(protocol, **kwargs)
        except KeyError:
            raise ValueError(
                f"Unknown protocol type '{protocol.type}' while transforming uniproxy protocol to clash protocol"
            )
    else:
        raise ValueError(f"Unknown protocol type: {type(protocol)}")
