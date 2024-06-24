from __future__ import annotations

from typing import Literal, TypeAlias

from attrs import frozen

from uniproxy.typing import ShadowsocksCipher

from .base import AbstractSurge, BaseProtocol


ProtocolOptions: TypeAlias = dict[str, str | None]


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

    def __str__(self):
        config: ProtocolOptions = {
            "skip-cert-verify": str(self.skip_cert_verify).lower(),
            "sni": self.sni,
            "server-cert-fingerprint-sha256": self.server_cert_fingerprint_sha256,
        }
        return ", ".join(f"{k}={v}" for k, v in config.items() if v is not None)


@frozen
class HttpProtocol(BaseProtocol):
    server: str
    port: int
    username: str | None = None
    password: str | None = None
    tls: SurgeTLS | None = None

    tfo: bool = False
    always_use_connect: bool | None = None

    type: Literal["http", "https"] = "http"


@frozen
class Socks5Protocol(BaseProtocol):
    server: str
    port: int
    username: str | None = None
    password: str | None = None
    tls: SurgeTLS | None = None

    udp_relay: bool = False

    type: Literal["socks5", "socks5-tls"] = "socks5"

    def as_dict(self) -> dict:
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
            f", {self.username}, {self.password}"
            if self.username and self.password
            else ""
        )
        return {
            self.name: f"{protocl}, {self.server}, {self.port}" + auth_ops + tls_opt
        }


class ShadowsocksProtocol(BaseProtocol):
    server: str
    port: int
    password: str
    encrypt_method: ShadowsocksCipher

    udp_relay: bool = True

    obfs: Literal["http", "tls"] | None = None
    obfs_host: str | None = None
    obfs_uri: str | None = None

    type = "ss"

    def as_dict(self) -> dict:
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
        }
        ss_opts = ",".join(f"{k}={v}" for k, v in ss_conf.items())

        return {
            self.name: (
                f"{self.type}, {self.server}, {self.port}, "
                + ss_opts
                + (", " + obfs_opts if obfs_opts else "")
            )
        }


@frozen
class SurgeVmessTransport(AbstractSurge):
    path: str | None = None
    headers: dict[str, str] | None = None
    encrypt_method: Literal["chacha20-ietf-poly1305", "aes-128-gcm"] | None = None
    vmess_aead: bool = False

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
            "ws": self.type,
            "ws-path": self.path,
            "ws-headers": ws_headers,
            "encrypt-method": self.encrypt_method,
            "vmess-aead": str(self.vmess_aead).lower(),
        }
        return ", ".join(f"{k}={v}" for k, v in opts.items() if v is not None)


@frozen
class VmessProtocol(BaseProtocol):
    server: str
    port: int

    username: str
    """uuid"""

    tls: SurgeTLS | None = None
    transport: SurgeVmessTransport | None = None

    type: Literal["vmess"] = "vmess"

    def as_dict(self) -> ProtocolOptions:
        """
        Ini example:

        ```ini
        ProxyVMess = vmess, 1.2.3.4, 8000, username=0233d11c-15a4-47d3-ade3-48ffca0ce119
        ```
        """
        tls_opts = str(self.tls) if self.tls else None
        ws_opts = str(self.transport) if self.transport else None

        valid: list[str] = list(filter(lambda x: x is not None and x != "", (tls_opts, ws_opts)))  # type: ignore
        extra_opts = (", " + ", ".join(valid)) if valid else ""

        return {
            self.name: (
                f"vmess, {self.server}, {self.port}, "
                f"username={self.username}"  # Do not end with comma for this line
                f"{extra_opts}"
            )
        }
