from __future__ import annotations

from typing import Any, Literal

from enum import StrEnum

from attrs import frozen

from uniproxy.base import BaseProtocol
from uniproxy.shared import TLS
from uniproxy.typing import Network, ProtocolType, ProtocolTypeEnum


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


class ShadowsocksCipherEnum(StrEnum):
    AEAD_AES_128_GCM = "aes-128-gcm"
    ADAD_AES_256_GCM = "aes-256-gcm"
    AEAD_CHACHA20_IETF_POLY1305 = "chacha20-ietf-poly1305"
    AEAD_2022_BLAKE3_AES_128_GCM = "2022-blake3-aes-128-gcm"
    AEAD_2022_BLAKE3_AES_256_GCM = "2022-blake3-aes-256-gcm"
    AEAD_2022_BLAKE3_CHACHA20_POLY1305 = "2022-blake3-chacha20-poly1305"
    AEAD_2022_BLAKE3_CHACHA8_POLY1305 = "2022-blake3-chacha8-poly1305"


ShadowsocksCipher = Literal[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
]


class ShadowsocksPlugin:
    command: Literal["obfs-local", "v2ray-plugin"] | str
    opts: str


@frozen
class ShadowsocksProtocol(BaseProtocol):
    password: str
    method: ShadowsocksCipher
    network: Network = "tcp_and_udp"
    plugin: ShadowsocksPlugin | None = None
    type: Literal["shadowsocks"] = "shadowsocks"

    # surge_extra: None = None
    "test-udp=google.com@1.1.1.1"

    def as_clash(self) -> dict[str, Any]:
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

    def as_surge(self) -> dict:
        """
        ini example:

        ```ini
        Proxy-SS = ss, 1.2.3.4, 8000, encrypt-method=chacha20-ietf-poly1305, password=abcd1234, udp-relay=true
        ```
        """
        return {
            self.name: (
                f"ss, {self.server}, {self.port}, "
                f"encrypt-method={self.method}, password={self.password}, "
                f"udp-relay={'true' if self.network != 'tcp' else 'false'}, ecn=true"
            )
        }


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

    def as_surge(self) -> dict:
        """
        Ini example:

        ```ini
        ProxyVMess = vmess, 1.2.3.4, 8000, username=0233d11c-15a4-47d3-ade3-48ffca0ce119
        ```
        """
        skip_cert_verify_opt = (
            "skip-cert-verify=true" if self.skip_cert_verify else None
        )

        if self.sni is False:
            sni_opt = "sni=off"
        elif self.sni:
            sni_opt = f"sni={self.sni}"
        else:
            sni_opt = None

        ws_opts = self.ws.as_surge_inline() if self.ws else None

        encrypt_method = (
            f"encrypt-method={self.method}" if self.method != "auto" else None
        )

        valid = tuple(
            filter(None, (skip_cert_verify_opt, sni_opt, ws_opts, encrypt_method))
        )
        extra_opts = (", " + ", ".join(valid)) if valid else ""

        return {
            self.name: (
                f"vmess, {self.server}, {self.port}, "
                f"username={self.uuid}"  # Do not end with comma for this line
                f"{extra_opts}"
            )
        }


@frozen
class WGPeer:
    endpoint: str
    public_key: str
    allowed_ips: str | None
    keepalive: int | None
    preshared_key: str | None
    reserved_bits: list[int] | None


@frozen
class WireGuard:
    name: str
    host: str
    port: int
    private_key: str
    peers: list[WGPeer]
    dns: list
    mtu: int
    reserved_bits: list[int] | None
    type: Literal["wireguard"] = "wireguard"
