from __future__ import annotations

from typing import Literal

from os import PathLike

from attrs import frozen

from uniproxy.typing import Network, ProtocolType

from .base import BaseProtocol


@frozen
class TLS:
    server_name: str | None = None
    enable_sni: bool | None = None
    alpn: list[str] | None = None
    verify: bool = True
    cert_ca: str | PathLike | None = None
    cert_private_key: str | PathLike | None = None
    cert_private_password: str | None = None


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
            "type": ProtocolType.SOCKS5.value,
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
        if self.tls or self.type == ProtocolType.SOCKS5_TLS:
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
