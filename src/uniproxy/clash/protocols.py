from __future__ import annotations

from typing import Literal

from attrs import frozen

from uniproxy.typing import ProtocolType

from .base import BaseClashProtocol


@frozen
class HttpProtocol(BaseClashProtocol):
    username: str
    password: str
    tls: bool
    skip_cert_verify: bool

    type: Literal["http", "https"] = "http"


@frozen
class Socks5Protocol(BaseClashProtocol):
    username: str | None = None
    password: str | None = None
    tls: bool | None = None
    skip_cert_verify: bool = False
    udp: bool = True

    type: Literal["socks5", "socks5-tls"] = "socks5"

    def as_dict(self) -> dict:
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
            {"tls": self.tls, "skip-cert-verify": self.skip_cert_verify}
            if self.tls
            else {}
        )

        return {
            "name": self.name,
            "type": ProtocolType.SOCKS5.value,
            "server": self.host,
            "port": self.port,
            "udp": self.udp,
            **auth_opts,
            **tls_opts,
        }


class ShadowsocksPlugin:
    command: Literal["obfs-local", "v2ray-plugin"] | str
    opts: str


@frozen
class ShadowsocksProtocol(BaseClashProtocol):
    cipher: ShadowsocksCipher
    password: str
    udp: bool
    plugin: ShadowsocksPlugin | None = None
    type: Literal["shadowsocks"] = "shadowsocks"


    def as_dict(self) -> dict[str, Any]:
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
        return {
            "name": self.name,
            "type": "ss",
            "server": self.server,
            "port": self.port,
            "cipher": self.method,
            "password": self.password,
            "udp": True if self.network != "tcp" else False,
        }


VmessCipher = Literal["none", "auto", "zero", "aes-128-gcm", "chacha20-poly1305"]


class VmessCipherEnum(StrEnum):
    NONE = "none"
    AUTO = "auto"
    ZERO = "zero"
    AES_128_GCM = "aes-128-gcm"
    CHACHA20_POLY1305 = "chacha20-pol1305"


VmessTransport = Literal["http", "ws", "grpc", "h2"]


class VmessTransportEnum(StrEnum):
    HTTP = "http"
    WS = "ws"
    GRPC = "grpc"
    H2 = "h2"


@frozen
class BaseVmessTransport:
    type: VmessTransport


@frozen
class VmessWsTransport:
    path: str | None
    headers: dict[str, str] | None = None
    type = "ws"

    def as_dict(self) -> dict:
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


@frozen
class VmessProtocol(BaseClashProtocol):
    uuid: str
    alter_id: int = 0
    security: VmessCipher = "auto"
    network: Network = "tcp"
    tls: TLS | None = None
    transport: BaseVmessTransport | None = None
    type: Literal["vmess"] = "vmess"

    def as_dict(self) -> dict:
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
