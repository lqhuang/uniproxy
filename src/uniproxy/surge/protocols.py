from __future__ import annotations

from typing import Literal

from attrs import frozen

from uniproxy.typing import ProtocolType

from .base import BaseSurgeProtocol


@frozen
class HttpProtocol(BaseProtocol):
    username: str
    password: str
    tls: bool
    skip_cert_verify: bool

    type: Literal["http", "https"] = "http"


@frozen
class Socks5Protocol(BaseProtocol):
    username: str | None = None
    password: str | None = None
    tls: bool | None = None
    skip_cert_verify: bool = False
    udp: bool = True

    type: Literal["socks5", "socks5-tls"] = "socks5"

    def as_dict(self) -> dict:
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

    def as_dict_inline(self) -> str:
        return f"ws=true, ws-path={self.path}"


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

        ws_opts = self.ws.as_dict_inline() if self.ws else None

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

