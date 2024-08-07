from __future__ import annotations

from typing import Literal
from uniproxy.typing import (
    Network,
    ProtocolType,
    ShadowsocksCipher,
    VmessCipher,
    VmessTransport,
)

from attrs import define

from uniproxy.base import BaseProtocol
from uniproxy.shared import TLS


@define
class UniproxyProtocol(BaseProtocol): ...


@define
class HttpProtocol(UniproxyProtocol):
    username: str
    password: str
    tls: TLS | None = None

    type: Literal["http", "https"] = "http"


@define
class QuicProtocol(UniproxyProtocol):
    username: str
    password: str
    tls: TLS

    type: Literal["quic"] = "quic"


@define
class Socks5Protocol(UniproxyProtocol):
    username: str | None = None
    password: str | None = None
    tls: TLS | None = None
    network: Network = "tcp_and_udp"

    type: Literal["socks5", "socks5-tls"] = "socks5"


@define
class ShadowsocksPlugin:
    """SIP003 plugin for shadowsocks."""

    command: str
    opts: str


@define
class ShadowsocksObfsLocalPlugin:
    mode: Literal["tls", "http"]
    host: str
    command: Literal["obfs"] | str = "obfs-local"


@define
class ShadowsocksObfsServerPlugin:
    mode: Literal["tls", "http"]
    host: str
    command: Literal["obfs"] | str = "obfs-server"


@define
class ShadowsocksV2RayPlugin:
    mode: Literal["websocket", "quic"]
    host: str
    path: str
    tls: bool | None = None
    skip_cert_verify: bool | None = None
    headers: dict[str, str] | None = None
    server: bool = False
    command: Literal["v2ray-plugin"] | str = "v2ray-plugin"


@define
class ShadowsocksProtocol(UniproxyProtocol):
    password: str
    method: ShadowsocksCipher
    network: Network = "tcp_and_udp"

    plugin: (
        ShadowsocksPlugin
        | ShadowsocksObfsServerPlugin
        | ShadowsocksObfsLocalPlugin
        | ShadowsocksV2RayPlugin
        | None
    ) = None

    type: Literal["shadowsocks"] = "shadowsocks"


@define
class ShadowsocksServer(ShadowsocksProtocol): ...


@define
class ShadowsocksLocal(ShadowsocksProtocol): ...


class TrojanProtocol: ...


@define
class TuicProtocol(UniproxyProtocol):
    token: str
    version: int
    tls: TLS
    disable_sni: bool = False
    udp_mode: Literal["naive", "quic"] = "quic"
    congestion_control: Literal["cubic", "new_reno", "bbr"] = "bbr"
    reduce_rtt: bool = False
    type: Literal["tuic"] = "tuic"


@define
class NaiveProtocol(UniproxyProtocol):
    username: str
    password: str
    proto: Literal["http2", "quic"]
    extra_headers: dict[str, str] | None = None
    type: ProtocolType = "naive"


@define
class BaseVmessTransport:
    type: VmessTransport


@define
class VmessWsTransport:
    path: str | None
    headers: dict[str, str] | None = None
    max_early_data: int | None = None
    early_data_header_name: str | None = None

    type: Literal["ws"] = "ws"


@define
class VmessH2Transport(BaseVmessTransport):
    path: str | None
    headers: dict[str, str] | None = None
    type: Literal["h2"] = "h2"


@define
class VmessProtocol(UniproxyProtocol):
    uuid: str
    alter_id: int = 0
    security: VmessCipher = "auto"
    network: Network = "tcp"
    tls: TLS | None = None
    transport: VmessWsTransport | VmessH2Transport | None = None

    type: Literal["vmess"] = "vmess"
