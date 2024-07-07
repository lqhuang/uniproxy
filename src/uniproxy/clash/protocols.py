from __future__ import annotations

from typing import Literal, cast
from uniproxy.typing import ShadowsocksCipher, VmessCipher, VmessTransport

from attrs import define, field, fields

from uniproxy.protocols import (
    ShadowsocksObfsLocalPlugin as UniproxyShadowsocksObfsPlugin,
)
from uniproxy.protocols import ShadowsocksProtocol as UniproxyShadowsocksProtocol
from uniproxy.protocols import ShadowsocksV2RayPlugin as UniproxyShadowsocksV2RayPlugin
from uniproxy.protocols import UniproxyProtocol
from uniproxy.protocols import VmessH2Transport as UniproxyVmessH2Transport
from uniproxy.protocols import VmessProtocol as UniproxyVmessProtocol
from uniproxy.protocols import VmessWsTransport as UniproxyVmessWsTransport

from .base import BaseProtocol


@define
class ClashProtocol(BaseProtocol):

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyProtocol, **kwargs) -> ClashProtocol:
        for subcls in cls.__subclasses__():
            _fields = fields(subcls)
            clash_type = _fields.type.default
            clash_type = "shadowsocks" if clash_type == "ss" else clash_type
            if clash_type == protocol.type:
                inst = subcls.from_uniproxy(protocol)
                break
        else:
            raise NotImplementedError(f"Unknown protocol type: {protocol.type}")

        return inst

    def to_uniproxy(self, **kwargs) -> UniproxyProtocol:
        return self.to_uniproxy()

    def __str__(self) -> str:
        return str(self.name)


@define
class HttpProtocol(ClashProtocol):
    username: str
    password: str
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
    skip_cert_verify: bool = False

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
        cls, protocol: UniproxyShadowsocksProtocol
    ) -> ShadowsocksProtocol:

        plugin = protocol.plugin.command if protocol.plugin else None

        plugin_opts: ShadowsocksPluginObfsOpts | ShadowsocksPluginV2RayOpts | None
        match plugin:
            case "obfs-local":
                plug = cast(UniproxyShadowsocksObfsPlugin, protocol.plugin)
                plugin_opts = ShadowsocksPluginObfsOpts(
                    mode=plug.mode,
                    host=plug.host,
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
    alterId: int = 0
    cipher: VmessCipher = "auto"
    udp: bool | None = None
    tls: bool = True
    skip_cert_verify: bool | None = None
    servername: str | None = None
    """
    overwrite the server name defined in 'ws-opts'/'h2-opts'
    """

    network: VmessTransport | None = "ws"
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
    def from_uniproxy(cls, protocol: UniproxyVmessProtocol) -> VmessProtocol:
        if protocol.tls is not None:
            skip_cert_verify = not protocol.tls.verify
            servername = protocol.tls.server_name
        else:
            skip_cert_verify = None
            servername = None

        if transport := protocol.transport is not None:
            network = protocol.transport.type
            match network:
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
                        path=h2_transport.path,
                        headers=h2_transport.headers,
                    )
                case _:
                    raise NotImplementedError(f"Unknown transport type: {network}")
        else:
            network = None

        return cls(
            protocol.name,
            protocol.server,
            protocol.port,
            uuid=protocol.uuid,
            alterId=protocol.alter_id,
            cipher=protocol.security,
            tls=True if protocol.tls else False,
            skip_cert_verify=skip_cert_verify,
            udp=protocol.network != "tcp",
            servername=servername,
            network=network,
            ws_opts=ws_opts,
            h2_opts=h2_opts,
        )
