from __future__ import annotations

from typing import Literal

from enum import StrEnum

from attrs import frozen

from uniproxy.typing import Network

from .base import BaseProtocol
from .std import TLS

__all__ = (
    "VmessCipher",
    "VmessCipherEnum",
    "VmessTransport",
    "VmessTransportEnum",
    "VmessProtocol",
    "VmessWSTransport",
)

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
class VmessWSTransport:
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
                f"vmess, {self.server}, {self.port}, "
                f"username={self.uuid}"  # Do not end with comma for this line
                f"{extra_opts}"
            )
        }
