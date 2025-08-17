from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import (
    Network,
    NetworkCIDR,
    ProtocolType,
    ShadowsocksCipher,
    VmessCipher,
)

from ipaddress import IPv4Address

from attrs import define

from uniproxy.base import BaseProtocol
from uniproxy.shared import TLS
from uniproxy.uri import parse_ss_uri


@define
class HttpProtocol(BaseProtocol):
    username: str | None = None
    password: str | None = None
    tls: TLS | None = None

    type: Literal["http", "https"] = "http"


@define
class QuicProtocol(BaseProtocol):
    username: str
    password: str
    tls: TLS

    type: Literal["quic"] = "quic"


@define
class Socks5Protocol(BaseProtocol):
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
class ShadowsocksObfsPlugin:
    obfs: Literal["tls", "http"]
    obfs_host: str
    command: Literal["obfs", "obfs-local"] = "obfs"


@define
class ShadowsocksObfsServerPlugin:
    obfs: Literal["tls", "http"]
    command: Literal["obfs-server"] = "obfs-server"


@define
class ShadowsocksV2RayPlugin:
    mode: Literal["websocket", "quic"]
    host: str
    path: str
    tls: bool | None = None
    skip_cert_verify: bool | None = None
    headers: dict[str, str] | None = None
    server: bool = False
    command: Literal["v2ray-plugin"] = "v2ray-plugin"


@define
class ShadowsocksProtocol(BaseProtocol):
    password: str
    method: ShadowsocksCipher
    network: Network = "tcp_and_udp"

    plugin: (
        ShadowsocksPlugin
        | ShadowsocksObfsPlugin
        | ShadowsocksObfsServerPlugin
        | ShadowsocksV2RayPlugin
        | None
    ) = None

    type: Literal["shadowsocks"] = "shadowsocks"

    @classmethod
    def from_uri(cls, uri: str, **kwargs) -> ShadowsocksProtocol:
        kwargs.setdefault("network", "tcp_and_udp")
        merged = {**parse_ss_uri(uri), **kwargs}
        return cls(**merged)


@define
class ShadowsocksServer(ShadowsocksProtocol): ...


@define
class ShadowsocksLocal(ShadowsocksProtocol): ...


@define
class TrojanProtocol(BaseProtocol):
    password: str
    tls: TLS | None = None
    network: Network = "tcp_and_udp"

    type: Literal["trojan"] = "trojan"


@define
class TuicProtocol(BaseProtocol):
    token: str
    tls: TLS

    udp_mode: Literal["naive", "quic"] = "quic"
    """
    Set the UDP relay mode. Available: "native", "quic".

    Default: "native"
    """

    congestion_control: Literal["cubic", "new_reno", "bbr"] = "bbr"
    """
    Set the congestion control algorithm. Available: "cubic", "new_reno", "bbr".

    Default: "cubic"
    """

    heartbeat_interval: float | None = None
    """
    Set the heartbeat interval to ensures that the QUIC connection is not
    closed when there are relay tasks but no data transfer, in milliseconds.

    Default: 10000
    """

    reduce_rtt: bool | None = False
    """Enable 0-RTT QUIC handshake"""

    type: Literal["tuic"] = "tuic"


@define
class NaiveProtocol(BaseProtocol):
    username: str
    password: str
    proto: Literal["http2", "quic"]
    extra_headers: dict[str, str] | None = None
    type: ProtocolType = "naive"


@define
class BaseVmessTransport:
    path: str | None


@define
class VmessWsTransport:
    headers: dict[str, str] | None = None
    max_early_data: int | None = None
    early_data_header_name: str | None = None

    type: Literal["ws"] = "ws"


@define
class VmessH2Transport(BaseVmessTransport):
    headers: dict[str, str] | None = None
    type: Literal["h2"] = "h2"


type VmessTransport = VmessWsTransport | VmessH2Transport


@define
class VmessProtocol(BaseProtocol):
    uuid: str
    alter_id: int = 0
    security: VmessCipher = "auto"
    network: Network = "tcp"
    tls: TLS | None = None
    transport: VmessWsTransport | VmessH2Transport | None = None

    type: Literal["vmess"] = "vmess"


@define
class WireGuardProtocol(BaseProtocol):
    private_key: str
    peer: WireGuardPeer
    address: IPv4Address | IPv4Address | str | None = None
    persistent_keepalive: int | None = None
    type: Literal["wireguard"] = "wireguard"


@define
class WireGuardPeer:
    public_key: str
    pre_shared_key: str | None = None
    allowed_ips: Sequence[NetworkCIDR] = ["0.0.0.0/0", "::/0"]
    persistent_keepalive: int | None = None


type UniproxyProtocol = (
    HttpProtocol
    | QuicProtocol
    | Socks5Protocol
    | ShadowsocksProtocol
    | TrojanProtocol
    | TuicProtocol
    | NaiveProtocol
    | VmessProtocol
    | WireGuardProtocol
)
