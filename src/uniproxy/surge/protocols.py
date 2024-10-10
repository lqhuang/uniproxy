from __future__ import annotations

from typing import Literal, Mapping, Sequence
from uniproxy.typing import ALPN, IPAddress
from uniproxy.typing import ProtocolType as UniproxyProtocolType
from uniproxy.typing import ShadowsocksCipher, VmessCipher

from ipaddress import IPv4Address, IPv6Address

from attrs import define

from uniproxy.protocols import HttpProtocol as UniproxyHttpProtocol
from uniproxy.protocols import ShadowsocksProtocol as UniproxyShadowsocksProtocol
from uniproxy.protocols import TrojanProtocol as UniproxyTrojanProtocol
from uniproxy.protocols import TuicProtocol as UniproxyTuicProtocol
from uniproxy.protocols import UniproxyProtocol
from uniproxy.protocols import VmessProtocol as UniproxyVmessProtocol

from .base import AbstractSurge, BaseProtocol
from .shared import SurgeTLS
from .typing import _ProtocolOptions

__all__ = [
    "HttpProtocol",
    "Socks5Protocol",
    "ShadowsocksProtocol",
    "VmessProtocol",
    "VmessTransport",
    "TrojanProtocol",
    "TuicProtocol",
    "WireguardProtocol",
    "WireguardPeer",
    "WireguardSection",
    "make_protocol_from_uniproxy",
]


@define
class SurgeProtocol(BaseProtocol):
    @classmethod
    def from_uniproxy(cls, protocol, **kwargs) -> SurgeProtocol:
        raise NotImplementedError

    def to_uniproxy(self, **kwargs) -> UniproxyProtocol:
        return self.to_uniproxy()


@define
class HttpProtocol(SurgeProtocol):
    username: str | None = None
    password: str | None = None
    tls: SurgeTLS | None = None

    tfo: bool = False
    always_use_connect: bool | None = None

    type: Literal["http", "https"] = "http"

    def __attrs_asdict__(self):
        """
        Config (ini) example:

        ```ini
        ProxyHTTP = http, 1.2.3.4, 443, username, password
        ProxyHTTPS = https, 1.2.3.4, 443, username, password, skip-cert-verify=true
        ```
        """
        if self.type == "https":
            protocl = "socks5-tls"
            tls_opt = str(self.tls) if self.tls else ""
        else:
            protocl = "socks5"
            tls_opt = ""

        auth_opt = (
            f"{self.username}, {self.password}"
            if self.username and self.password
            else ""
        )

        must_opts = f"{protocl}, {self.server}, {self.port}"
        return {
            self.name: ", ".join(
                filter(lambda x: bool(x), (must_opts, auth_opt, tls_opt))
            )
        }

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyHttpProtocol, **kwargs) -> HttpProtocol:
        tls = None if protocol.tls is None else SurgeTLS.from_uniproxy(protocol.tls)
        return cls(
            name=protocol.name,
            server=protocol.server,
            port=protocol.port,
            username=protocol.username,
            password=protocol.password,
            tls=tls,
            always_use_connect=False,
            type=protocol.type,
        )


@define
class Socks5Protocol(SurgeProtocol):
    username: str | None = None
    password: str | None = None
    tls: SurgeTLS | None = None

    udp_relay: bool | None = None

    type: Literal["socks5", "socks5-tls"] = "socks5"

    def __attrs_post_init__(self):
        if self.tls is not None:
            self.type = "socks5-tls"

    def __attrs_asdict__(self):
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

        auth_opt = (
            f"{self.username}, {self.password}"
            if self.username and self.password
            else ""
        )

        udp_opt = (
            f"udp-relay={str(self.udp_relay).lower()}"
            if self.udp_relay is not None
            else ""
        )

        must_opts = f"{protocl}, {self.server}, {self.port}"
        return {
            self.name: ", ".join(
                filter(lambda x: bool(x), (must_opts, auth_opt, tls_opt, udp_opt))
            )
        }


@define
class ShadowsocksProtocol(SurgeProtocol):
    password: str
    encrypt_method: ShadowsocksCipher

    udp_relay: bool | None = None

    obfs: Literal["http", "tls"] | None = None
    obfs_host: str | None = None
    obfs_uri: str | None = None

    ecn: bool | None = None

    type: Literal["ss"] = "ss"

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

    def __attrs_asdict__(self):
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
            # FIXME: incorrect position
            "ecn": str(self.ecn).lower() if self.ecn is not None else None,
        }
        ss_opts = ", ".join(f"{k}={v}" for k, v in ss_conf.items() if v is not None)

        return {
            self.name: (
                f"{self.type}, {self.server}, {self.port}, "
                + ss_opts
                + (", " + obfs_opts if obfs_opts else "")
            )
        }


@define
class VmessTransport(AbstractSurge):
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

        opts: _ProtocolOptions = {
            "ws": "true",
            "ws-path": self.path,
            "ws-headers": ws_headers,
            "vmess-aead": (
                str(self.vmess_aead).lower() if self.vmess_aead is not None else None
            ),
        }
        return ", ".join(f"{k}={v}" for k, v in opts.items() if v is not None)


@define
class VmessProtocol(SurgeProtocol):
    username: str
    """uuid"""

    encrypt_method: VmessCipher | None = None
    tls: SurgeTLS | None = None
    transport: VmessTransport | None = None

    type: Literal["vmess"] = "vmess"

    def __attrs_asdict__(self):
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

        if protocol.security in {"chacha20-ietf-poly1305", "aes-128-gcm"}:
            encrypt_method = protocol.security
        else:
            encrypt_method = None

        return cls(
            name=protocol.name,
            server=protocol.server,
            port=protocol.port,
            username=protocol.uuid,
            encrypt_method=encrypt_method,
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
                else VmessTransport(
                    path=protocol.transport.path,
                    headers=protocol.transport.headers,
                )
            ),
            **kwargs,
        )


@define
class TrojanProtocol(SurgeProtocol):
    password: str
    tls: SurgeTLS | None = None

    udp_relay: bool | None = None

    type: Literal["trojan"] = "trojan"

    def __attrs_asdict__(self):
        """
        Config (ini) example:

        ```ini
        Proxy-Trojan = trojan, 192.168.20.6, 443, password=password1
        ```
        """
        must_opts = f"{self.type}, {self.server}, {self.port}, password={self.password}"
        tls_opts = str(self.tls) if self.tls else ""
        udp_opts = (
            f"udp-relay={str(self.udp_relay).lower()}"
            if self.udp_relay is not None
            else ""
        )
        return {self.name: ", ".join(filter(bool, (must_opts, tls_opts, udp_opts)))}

    @classmethod
    def from_uniproxy(
        cls, protocol: UniproxyTrojanProtocol, **kwargs
    ) -> TrojanProtocol:
        return cls(
            name=protocol.name,
            server=protocol.server,
            port=protocol.port,
            password=protocol.password,
            tls=SurgeTLS.from_uniproxy(protocol.tls) if protocol.tls else None,
            udp_relay=UniproxyTrojanProtocol.network != "tcp",
        )


@define
class TuicProtocol(SurgeProtocol):
    """
    ```ini
    [Proxy]
    Proxy-TUIC = tuic, 192.168.20.6, 443, token=pwd, alpn=h3
    ```
    """

    token: str
    alpn: ALPN | None = None

    tls: SurgeTLS | None = None
    udp_relay: bool | None = True

    type: Literal["tuic"] = "tuic"

    def __attrs_asdict__(self) -> dict:
        must_opts = f"{self.type}, {self.server}, {self.port}, token={self.token}"
        alpn_opts = f"alpn={self.alpn}" if self.alpn is not None else ""
        tls_opts = str(self.tls) if self.tls else ""
        udp_opts = (
            f"udp-relay={str(self.udp_relay).lower()}"
            if self.udp_relay is not None
            else ""
        )
        return {
            self.name: ", ".join(
                filter(bool, (must_opts, alpn_opts, tls_opts, udp_opts))
            )
        }

    @classmethod
    def from_uniproxy(cls, protocol: UniproxyTuicProtocol, **kwargs) -> TuicProtocol:
        tls = protocol.tls
        return cls(
            name=protocol.name,
            server=protocol.server,
            port=protocol.port,
            token=protocol.token,
            alpn=tls.alpn[0] if tls.alpn else None,
            udp_relay=True,
            **kwargs,
        )


class WireguardProtocol(SurgeProtocol):
    """
    ```ini
    [Proxy]
    wireguard-home = wireguard, section-name = HomeServer
    ```
    """

    section_name: str | WireguardSection
    type: Literal["wireguard"] = "wireguard"


class WireguardPeer(AbstractSurge):
    """
    ```ini
    [WireGuard HomeServer]
    ...
    peer = (public-key = fWO8XS9/nwUQcqnkfBpKeqIqbzclQ6EKP20Pgvzwclg=, allowed-ips = 0.0.0.0/0, endpoint = 192.168.20.6:51820)
    ...
    ```

    Customize Reserved Bits
    -----------------------

    Surge supports customizing the reserved bits of WireGuard. It might be used as the client ID or routing ID for some implementations, such as Cloudflare WARP.

    Example:
    ```
    [WireGuard HomeServer]
    ...
    peer = (public-key = <key>, allowed-ips = "0.0.0.0/0, ::/0", endpoint = example.com:51820, client-id = 83/12/235)
    ...
    ```
    """

    endpoint: str
    public_key: str
    allowed_ips: Sequence[str]
    client_id: tuple[int, int, int] | None = None

    def __attrs_asdict__(self):
        peer = {
            "public-key": self.public_key,
            "allowed-ips": self.allowed_ips,
            "endpoint": self.endpoint,
            "client-id": self.client_id,
        }
        return {"peer": peer}


class WireguardSection(AbstractSurge):
    """
    ```ini
    [WireGuard HomeServer]
    private-key = sDEZLACT3zgNCS0CyClgcBC2eYROqYrwLT4wdtAJj3s=
    self-ip = 10.0.2.2
    self-ip-v6 = fd00:1111::11
    dns-server = 8.8.8.8, 2606:4700:4700::1001
    prefer-ipv6 = false
    mtu = 1280
    peer = (public-key = fWO8XS9/nwUQcqnkfBpKeqIqbzclQ6EKP20Pgvzwclg=, allowed-ips = 0.0.0.0/0, endpoint = 192.168.20.6:51820)
    ```

    Notes for configuration:
    """

    name: str

    private_key: str
    peer: WireguardPeer
    self_ip: str | IPv4Address | None = None
    self_ip_v6: str | IPv6Address | None = None

    dns_server: Sequence[IPAddress] | None = None
    prefer_ipv6: bool | None = None
    mtu: int | None = None

    type: Literal["wireguard"] = "wireguard"

    def __attrs_asdict__(self):
        return {f"WireGuard {self.name}": {}}


_SURGE_MAPPER: Mapping[UniproxyProtocolType, type[SurgeProtocol]] = {
    "http": HttpProtocol,
    "https": HttpProtocol,
    "socks5": Socks5Protocol,
    "socks5-tls": Socks5Protocol,
    "shadowsocks": ShadowsocksProtocol,
    "vmess": VmessProtocol,
    "trojan": TrojanProtocol,
    "tuic": TuicProtocol,
    "wireguard": WireguardProtocol,
}


def make_protocol_from_uniproxy(protocol: UniproxyProtocol, **kwargs) -> SurgeProtocol:
    try:
        return _SURGE_MAPPER[protocol.type].from_uniproxy(protocol, **kwargs)
    except KeyError:
        raise ValueError(
            f"Unknown protocol type '{protocol.type}' when transforming uniproxy protocol to surge protocol"
        )
