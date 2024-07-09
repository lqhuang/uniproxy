from __future__ import annotations

from typing import Literal, TypeAlias
from uniproxy.typing import ShadowsocksCipher, VmessCipher

from attrs import define

from uniproxy.protocols import ShadowsocksProtocol as UniproxyShadowsocksProtocol
from uniproxy.protocols import VmessProtocol as UniproxyVmessProtocol

from .base import AbstractSurge, BaseProtocol

ProtocolOptions: TypeAlias = dict[str, str | None]


@define
class SurgeTLS(AbstractSurge):
    skip_cert_verify: bool = False
    """
    If this option is enabled, Surge will not verify the server's certificate.

    Optional, "true" or "false" (Default: false).
    """

    sni: Literal["off"] | str | None = None
    """
    Customize the Server Name Indication (SNI) during the TLS handshake.
    Use `sni=off` to turn off SNI completely. By default, Surge sends the SNI
    using the `hostname` like most browsers.
    """

    server_cert_fingerprint_sha256: str | None = None
    """
    Use a pinned server certificate instead of the standard X.509 validation.
    """

    def __str__(self) -> str:
        config: ProtocolOptions = {
            "skip-cert-verify": str(self.skip_cert_verify).lower(),
            "sni": self.sni,
            "server-cert-fingerprint-sha256": self.server_cert_fingerprint_sha256,
        }
        return ", ".join(f"{k}={v}" for k, v in config.items() if v is not None)


@define
class HttpProtocol(BaseProtocol):
    server: str
    port: int
    username: str | None = None
    password: str | None = None
    tls: SurgeTLS | None = None

    tfo: bool = False
    always_use_connect: bool | None = None

    type: Literal["http", "https"] = "http"


@define
class Socks5Protocol(BaseProtocol):
    username: str | None = None
    password: str | None = None
    tls: SurgeTLS | None = None

    udp_relay: bool = False

    type: Literal["socks5", "socks5-tls"] = "socks5"

    def __attrs_post_init__(self):
        if self.tls is not None:
            self.type = "socks5-tls"

    def asdict(self):
        """
        Config (ini) example:

        ```ini
        ProxySOCKS5 = socks5, 1.2.3.4, 443, username, password
        ProxySOCKS5TLS = socks5-tls, 1.2.3.4, 443, username, password, skip-cert-verify=true
        ```
        """
        if self.type == "socks5-tls":
            protocl = "socks5-tls"
            tls_opt = str(self.tls) if self.tls else ""
        else:
            protocl = "socks5"
            tls_opt = ""

        auth_ops = (
            f"{self.username}, {self.password}"
            if self.username and self.password
            else ""
        )

        must_opts = f"{protocl}, {self.server}, {self.port}"
        return {
            self.name: ", ".join(
                filter(lambda x: bool(x), (must_opts, auth_ops, tls_opt))
            )
        }


@define
class ShadowsocksProtocol(BaseProtocol):
    password: str
    encrypt_method: ShadowsocksCipher

    udp_relay: bool = False

    obfs: Literal["http", "tls"] | None = None
    obfs_host: str | None = None
    obfs_uri: str | None = None

    type: Literal["ss"] = "ss"

    def asdict(self):
        """
        Config (ini) example:

        ```ini
        Proxy-SS = ss, 1.2.3.4, 8000, encrypt-method=chacha20-ietf-poly1305, password=abcd1234
        ```
        """

        obfs_conf = {
            "obfs": self.obfs,
            "obfs-host": self.obfs_host,
            "obfs-uri": self.obfs_uri,
        }
        obfs_opts = ", ".join(f"{k}={v}" for k, v in obfs_conf.items() if v is not None)

        ss_conf = {
            "encrypt-method": self.encrypt_method,
            "password": self.password,
            "udp-relay": str(self.udp_relay).lower(),
        }
        ss_opts = ", ".join(f"{k}={v}" for k, v in ss_conf.items())

        return {
            self.name: (
                f"{self.type}, {self.server}, {self.port}, "
                + ss_opts
                + (", " + obfs_opts if obfs_opts else "")
            )
        }

    @classmethod
    def from_uniproxy(
        cls, protocol: UniproxyShadowsocksProtocol, **kwargs
    ) -> ShadowsocksProtocol:
        return cls(
            name=protocol.name,
            server=protocol.server,
            port=protocol.port,
            password=protocol.password,
            encrypt_method=protocol.method,
            udp_relay=protocol.network != "tcp",
            **kwargs,
        )


@define
class SurgeVmessTransport(AbstractSurge):
    path: str | None = None
    headers: dict[str, str] | None = None
    vmess_aead: bool | None = None

    type: Literal["ws"] = "ws"

    def __str__(self) -> str:
        if self.headers is not None:
            # Value format: `Header-1:value-1|Header-2:value-2`
            # Key and value is divided by colon
            # Entries are divided by vertical bar
            # Usable only when ws set to true
            ws_headers = "|".join(f"{k}:{v}" for k, v in self.headers.items())
        else:
            ws_headers = None

        opts: ProtocolOptions = {
            "ws": "true",
            "ws-path": self.path,
            "ws-headers": ws_headers,
            "vmess-aead": (
                str(self.vmess_aead).lower() if self.vmess_aead is not None else None
            ),
        }
        return ", ".join(f"{k}={v}" for k, v in opts.items() if v is not None)


@define
class VmessProtocol(BaseProtocol):
    username: str
    """uuid"""

    encrypt_method: VmessCipher | None = None
    tls: SurgeTLS | None = None
    transport: SurgeVmessTransport | None = None

    type: Literal["vmess"] = "vmess"

    def asdict(self):
        """
        Ini example:

        ```ini
        ProxyVMess = vmess, 1.2.3.4, 8000, username=0233d11c-15a4-47d3-ade3-48ffca0ce119
        ```
        """
        must_opts = f"{self.type}, {self.server}, {self.port}, username={self.username}"
        cipher_opts = (
            f"encrypt-method={self.encrypt_method}" if self.encrypt_method else None
        )
        tls_opts = str(self.tls) if self.tls else None
        ws_opts = str(self.transport) if self.transport else None

        return {
            self.name: ", ".join(
                i
                for i in (must_opts, cipher_opts, tls_opts, ws_opts)
                if i is not None and i != ""
            )
        }

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyVmessProtocol, **kwargs) -> VmessProtocol:
        if not isinstance(protocol, UniproxyVmessProtocol):
            raise TypeError("Invalid protocol type")

        if protocol.transport is not None and protocol.transport.type != "ws":
            raise ValueError("Only ws transport is supported for surge for now")

        return cls(
            name=protocol.name,
            server=protocol.server,
            port=protocol.port,
            username=protocol.uuid,
            encrypt_method=protocol.security,
            tls=(
                None
                if protocol.tls is None
                else SurgeTLS(
                    skip_cert_verify=True if not protocol.tls.verify else False,
                    sni=protocol.tls.server_name,
                    # server_cert_fingerprint_sha256=protocol.tls.cert_ca,
                )
            ),
            transport=(
                None
                if protocol.transport is None
                else SurgeVmessTransport(
                    path=protocol.transport.path,
                    headers=protocol.transport.headers,
                )
            ),
            **kwargs,
        )
