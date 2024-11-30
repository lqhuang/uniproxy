from __future__ import annotations

from typing import Any, Literal, Mapping, Sequence, cast
from uniproxy.typing import (
    ALPN,
    ProtocolType,
    ShadowsocksCipher,
    VmessCipher,
    VmessTransport,
)

from attrs import define, field
from xattrs._metadata import _Metadata

from uniproxy.protocols import ShadowsocksObfsPlugin as UniproxyShadowsocksObfsPlugin
from uniproxy.protocols import ShadowsocksProtocol as UniproxyShadowsocksProtocol
from uniproxy.protocols import ShadowsocksV2RayPlugin as UniproxyShadowsocksV2RayPlugin
from uniproxy.protocols import TrojanProtocol as UniproxyTrojanProtocol
from uniproxy.protocols import UniproxyProtocol
from uniproxy.protocols import VmessH2Transport as UniproxyVmessH2Transport
from uniproxy.protocols import VmessProtocol as UniproxyVmessProtocol
from uniproxy.protocols import VmessWsTransport as UniproxyVmessWsTransport

from .base import BaseProtocol


@define
class ClashProtocol(BaseProtocol):
    @classmethod
    def from_uniproxy(cls, protocol, **kwargs) -> ClashProtocol:
        raise NotImplementedError

    def to_uniproxy(self, **kwargs) -> UniproxyProtocol:
        return self.to_uniproxy()


@define
class HttpProtocol(ClashProtocol):
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


@define
class Socks5Protocol(ClashProtocol):
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
class ShadowsocksProtocol(ClashProtocol):
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
class TrojanProtocol(ClashProtocol):
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
    alpn: Sequence[ALPN] | None = None

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
class VmessProtocol(ClashProtocol):
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

    network: VmessTransport | None = None
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


_CLASH_MAPPER: Mapping[ProtocolType, type[ClashProtocol]] = {
    "http": HttpProtocol,
    "https": HttpProtocol,
    "socks5": Socks5Protocol,
    "socks5-tls": Socks5Protocol,
    "shadowsocks": ShadowsocksProtocol,
    "vmess": VmessProtocol,
    "trojan": TrojanProtocol,
    # "tuic": TuicProtocol,
    # "wireguard": WireguardProtocol,
}


def make_protocol_from_uniproxy(
    protocol: UniproxyProtocol | ClashProtocol | Any, **kwargs
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
