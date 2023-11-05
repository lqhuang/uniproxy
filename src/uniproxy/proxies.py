from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from attrs import frozen


class ProxyType(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    SOCKS5_TLS = "socks5-tls"
    SHADOWSOCKS = "ss"
    TUIC = "tuic"
    WIREGUARD = "wireguard"
    VMESS = "vmess"

    QUIC = "quic"
    SNELL = "snell"
    TROJAN = "trojan"


@frozen
class BaseProxy:
    name: str
    type: ProxyType
    host: str
    port: int

    @classmethod
    def from_toml(cls) -> BaseProxy:
        ...

    def as_clash(self) -> dict:
        raise NotImplementedError

    def as_surge(self) -> dict:
        raise NotImplementedError


@frozen
class HttpProxy(BaseProxy):
    username: str
    password: str
    tls: bool
    skip_cert_verify: bool

    type: Literal[ProxyType.HTTP, ProxyType.HTTPS] = ProxyType.HTTP


@frozen
class QuicProxy(BaseProxy):
    username: str
    password: str
    skip_cert_verify: bool

    type: Literal[ProxyType.QUIC] = ProxyType.QUIC


@frozen
class Socks4Proxy(BaseProxy):
    host: str
    port: int
    username: str
    password: str

    type: Literal[ProxyType.SOCKS4] = ProxyType.SOCKS4


@frozen
class Socks5Proxy(BaseProxy):
    username: str | None = None
    password: str | None = None
    tls: bool | None = None
    skip_cert_verify: bool = False
    udp: bool = True

    type: Literal[ProxyType.SOCKS5, ProxyType.SOCKS5_TLS] = ProxyType.SOCKS5

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
            {"tls": self.tls, "skip-cert-verify": self.skip_cert_verify}
            if self.tls
            else {}
        )

        return {
            "name": self.name,
            "type": ProxyType.SOCKS5.value,
            "server": self.host,
            "port": self.port,
            "udp": self.udp,
            **auth_opts,
            **tls_opts,
        }

    def as_surge(self) -> dict:
        """
        Config (ini) example:

        ```ini
        ProxySOCKS5 = socks5, 1.2.3.4, 443, username, password
        ProxySOCKS5TLS = socks5-tls, 1.2.3.4, 443, username, password, skip-cert-verify=true
        ```
        """
        if self.tls or self.type == ProxyType.SOCKS5_TLS:
            protocl = "socks5-tls"
            tls_opt = f", skip-cert-verify={str(self.skip_cert_verify).lower()}"
        else:
            protocl = "socks5"
            tls_opt = ""

        auth_ops = (
            f", {self.username}, {self.password}"
            if self.username and self.password
            else ""
        )
        return {self.name: f"{protocl}, {self.host}, {self.port}" + auth_ops + tls_opt}


class ShadowsocksCipher(StrEnum):
    AEAD_AES_128_GCM = "aes-128-gcm"
    ADAD_AES_256_GCM = "aes-256-gcm"
    AEAD_CHACHA20_IETF_POLY1305 = "chacha20-ietf-poly1305"
    AEAD_2022_BLAKE3_AES_128_GCM = "2022-blake3-aes-128-gcm"
    AEAD_2022_BLAKE3_AES_256_GCM = "2022-blake3-aes-256-gcm"
    AEAD_2022_BLAKE3_CHACHA20_POLY1305 = "2022-blake3-chacha20-poly1305"
    AEAD_2022_BLAKE3_CHACHA8_POLY1305 = "2022-blake3-chacha8-poly1305"


LiteralShadowsocksCipher = Literal[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
]


class SSPlugin:
    command: str
    opts: dict[str, Any]


@frozen
class ShadowsocksProxy(BaseProxy):
    method: ShadowsocksCipher | LiteralShadowsocksCipher
    password: str
    udp: bool = True
    plugin: SSPlugin | None = None

    type: Literal[ProxyType.SHADOWSOCKS] = ProxyType.SHADOWSOCKS

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
            "server": self.host,
            "port": self.port,
            "cipher": self.method,
            "password": self.password,
            "udp": self.udp,
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
                f"ss, {self.host}, {self.port}, "
                f"encrypt-method={self.method}, password={self.password}, "
                f"udp-relay={str(self.udp).lower()}"
            )
        }


class SSServer:
    method: ShadowsocksCipher | LiteralShadowsocksCipher
    password: str
    udp: bool = True
    plugin: SSPlugin | None = None


class WGPeer:
    endpoint: str
    public_key: str
    allowed_ips: str | None
    keepalive: int | None
    preshared_key: str | None
    reserved_bits: list[int] | None


class WireGuard:
    name: str
    host: str
    port: int
    private_key: str
    peers: list[WGPeer]
    dns: list
    mtu: int
    reserved_bits: list[int] | None

    type: Literal[ProxyType.WIREGUARD] = ProxyType.WIREGUARD


@frozen
class TuicProxy(BaseProxy):
    password: str
    uuid: str
    version: int
    sni: str | None
    skip_cert_verify: bool
    alpn: list[str]
    udp: bool

    type: Literal[ProxyType.TUIC] = ProxyType.TUIC


@frozen
class NaiveProxy(BaseProxy):
    ...


@frozen
class VmessWSOpt:
    path: str | None
    headers: dict[str, str] | None = None

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
class VmessProxy(BaseProxy):
    uuid: str
    alter_id: int = 0
    method: Literal["auto", "aes-128-gcm", "chacha20-poly1305", "none"] = "auto"
    udp: bool = False
    tls: bool | None = None
    skip_cert_verify: bool = False
    sni: str | Literal[False] | None = None  # servername in clash
    network: Literal["http", "ws", "grpc", "h2"] | None = None
    ws: VmessWSOpt | None = None

    type: Literal[ProxyType.VMESS] = ProxyType.VMESS

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
                "tls": self.tls,
                "skip-cert-verify": self.skip_cert_verify,
            }
            if self.tls
            else {}
        )
        servername_opt = {"servername": self.sni} if self.sni else {}
        if self.ws is not None and self.network in ("ws", None):
            ws_opts = {
                "network": "ws",
                "ws-opts": self.ws.as_clash(),
            }
        else:
            ws_opts = {}

        return {
            "name": self.name,
            "type": "vmess",
            "server": self.host,
            "port": self.port,
            "uuid": self.uuid,
            "alterId": self.alter_id,
            "cipher": self.method,
            "udp": self.udp,
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
                f"vmess, {self.host}, {self.port}, "
                f"username={self.uuid}"  # Do not end with comma for this line
                f"{extra_opts}"
            )
        }
