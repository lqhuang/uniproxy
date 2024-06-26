from __future__ import annotations

from typing import Literal

from attrs import frozen

from uniproxy.base import BaseProtocol
from uniproxy.shared import TLS
from uniproxy.typing import (
    Network,
    ProtocolType,
    ProtocolTypeEnum,
    ShadowsocksCipher,
    VmessCipher,
    VmessTransport,
)


@frozen
class HttpProtocol(BaseProtocol):
    username: str
    password: str
    tls: TLS | None = None

    type: Literal["http", "https"] = "http"


@frozen
class QuicProtocol(BaseProtocol):
    username: str
    password: str
    skip_cert_verify: bool

    type: Literal["quic"] = "quic"


@frozen
class Socks5Protocol(BaseProtocol):
    username: str | None = None
    password: str | None = None
    tls: TLS | None = None
    network: Network = "tcp_and_udp"

    type: Literal["socks5", "socks5-tls"] = "socks5"

    def as_clash(self) -> dict:
        """
        YAML example:

        ```yaml
        name: proxy-socks5
        type: socks5
        server: 127.0.0.1
        port: 1080
        # username: username
        # password: password
        # tls: true
        # skip-cert-verify: true
        # udp: true
        ```
        """
        auth_opts = (
            {
                "username": self.username,
                "password": self.password,
            }
            if self.username and self.password
            else {}
        )
        tls_opts = (
            {"tls": self.tls, "skip-cert-verify": not self.tls.verify}
            if self.tls
            else {}
        )

        return {
            "name": self.name,
            "type": ProtocolTypeEnum.SOCKS5.value,
            "server": self.server,
            "port": self.port,
            "udp": self.network != "tcp",
            **auth_opts,
            **tls_opts,
        }


@frozen
class ShadowsocksPlugin:
    """SIP003 plugin for shadowsocks."""

    command: Literal["obfs-local", "v2ray-plugin"] | str
    opts: str


@frozen
class ShadowsocksProtocol(BaseProtocol):
    password: str
    method: ShadowsocksCipher
    network: Network = "tcp_and_udp"
    plugin: ShadowsocksPlugin | None = None

    type: Literal["shadowsocks"] = "shadowsocks"


@frozen
class ShadowsocksServer(ShadowsocksProtocol): ...


@frozen
class ShadowsocksLocal(ShadowsocksProtocol): ...


class TrojanProtocol: ...


@frozen
class TuicProtocol(BaseProtocol):
    token: str
    version: int
    tls: TLS
    disable_sni: bool = False
    udp_mode: Literal["naive", "quic"] = "quic"
    congestion_control: Literal["cubic", "new_reno", "bbr"] = "bbr"
    reduce_rtt: bool = False
    type: Literal["tuic"] = "tuic"


@frozen
class NaiveProtocol(BaseProtocol):
    username: str
    password: str
    proto: Literal["http2", "quic"]
    extra_headers: dict[str, str] | None = None
    type: ProtocolType = "naive"


@frozen
class BaseVmessTransport:
    type: VmessTransport


@frozen
class VmessWsTransport:
    path: str | None
    headers: dict[str, str] | None = None

    type: Literal["ws"] = "ws"

    def as_clash(self) -> dict:
        """
        YAML example:

        ```yaml
        ws-opts:
          path: /path
          headers:
            Host: v2ray.com
        ```
        """
        headers = self.headers or {}
        return {"path": self.path, **headers}

    def as_surge_inline(self) -> str:
        return f"ws=true, ws-path={self.path}"


@frozen
class VmessProtocol(BaseProtocol):
    uuid: str
    alter_id: int = 0
    security: VmessCipher = "auto"
    network: Network = "tcp"
    tls: TLS | None = None
    transport: BaseVmessTransport | None = None

    type: Literal["vmess"] = "vmess"

    def as_clash(self) -> dict:
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
        tls_opt = (
            {
                "tls": True,
                "skip-cert-verify": not self.tls.verify,
            }
            if self.tls is not None
            else {}
        )
        servername_opt = {"servername": self.sni} if self.sni else {}
        if self.ws is not None and self.transport in ("ws", None):
            ws_opts = {
                "network": "ws",
                "ws-opts": self.ws.as_clash(),
            }
        else:
            ws_opts = {}

        return {
            "name": self.name,
            "type": "vmess",
            "server": self.server,
            "port": self.port,
            "uuid": self.uuid,
            "alterId": self.alter_id,
            "cipher": self.security,
            "udp": self.network != "tcp",
            **servername_opt,
            **tls_opt,
            **ws_opts,
        }
