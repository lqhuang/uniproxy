from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import ServerAddress

from abc import ABC
from os import PathLike

from attrs import define

from uniproxy.protocols import TLS as UniproxyTLS

from .base import BaseInbound
from .typing import DnsStrategy, TransportType


@define
class User:
    username: str
    password: str


@define
class ExternalAccount:
    key_id: str | None = None
    mac_key: str | None = None


@define
class DNS01Challenge:
    provider: Literal["cloudflare", "alidns"]


@define
class CloudflareDNS01Challenge(DNS01Challenge):
    provider: Literal["cloudflare"]
    api_token: str


@define
class AliDNS01Challenge(DNS01Challenge):
    provider: Literal["alidns"]
    access_key_id: str
    access_key_secret: str
    region_id: str


@define
class ACME:
    domain: Sequence[str] | None = None
    data_directory: str | None = None
    default_server_name: str | None = None
    email: str | None = None
    provider: Literal["letsencrypt", "zerossl"] | str | None = None
    disable_http_challenge: bool | None = None
    disable_tls_alpn_challenge: bool | None = None
    alternative_http_port: int | None = None
    alternative_tls_port: int | None = None
    external_account: ExternalAccount | None = None
    dns01_challenge: DNS01Challenge | None = None


@define
class ECH:
    enabled: bool | None = None
    pq_signature_schemes_enabled: bool | None = None
    dynamic_record_sizing_disabled: bool | None = None
    key: Sequence[str] | None = None
    key_path: str | None = None


@define
class UTLS:
    enabled: bool | None = None
    fingerprint: str | None = None


class BaseTLS(ABC): ...


@define
class InboundTLS:
    enabled: bool | None = None
    server_name: str | None = None
    alpn: Sequence[str] | None = None
    min_version: str | None = None
    max_version: str | None = None
    cipher_suites: Sequence[str] | None = None
    certificate: Sequence[str] | None = None
    certificate_path: PathLike | None = None
    key: Sequence[str] | None = None
    key_path: PathLike | None = None
    acme: ACME | None = None
    ech: ECH | None = None


@define
class OutboundTLS(BaseTLS):
    enabled: bool | None = None
    disable_sni: bool | None = None
    server_name: str | None = None
    insecure: bool | None = None
    alpn: Sequence[str] | None = None
    min_version: str | None = None
    max_version: str | None = None
    cipher_suites: Sequence[str] | None = None
    certificate: Sequence[str] | None = None
    certificate_path: PathLike | None = None
    ech: ECH | None = None
    utls: UTLS | None = None

    @classmethod
    def from_uniproxy(cls, tls: UniproxyTLS, **kwargs) -> OutboundTLS:
        return cls(
            enabled=tls is not None,
            disable_sni=not tls.enable_sni,
            server_name=tls.server_name,
            insecure=not tls.verify,
            alpn=tls.alpn,
        )


@define
class DialFields: ...


@define
class MixinListenFields:
    listen: str | None = None
    listen_port: int | None = None
    tcp_fast_open: bool | None = None
    tcp_multi_path: bool | None = None
    udp_fragment: bool | None = None

    udp_timeout: str | None = None
    """
    UDP NAT expiration time in seconds.

    `5m` is used by default.
    """
    detour: BaseInbound | str | None = None
    """
    If set, connections will be forwarded to the specified inbound.

    Requires target inbound support, see Injectable.
    """

    sniff: bool | None = None
    sniff_override_destination: bool | None = None
    sniff_timeout: str | None = None

    domain_strategy: DnsStrategy | None = None
    """
    One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.

    If set, the requested domain name will be resolved to IP before routing.

    If `sniff_override_destination` is in effect, its value will be taken as a fallback.
    """

    udp_disable_domain_unmapping: bool | None = None


class InboundMultiplex:
    enabled: bool | None = None
    padding: bool | None = None
    # brutal: dict | None = None


class OutboundMultiplex:
    """
    ```json
    {
        "enabled": true,
        "protocol": "smux",
        "max_connections": 4,
        "min_streams": 4,
        "max_streams": 0,
        "padding": false,
        "brutal": {},
    }
    ```
    """

    enabled: bool | None = None
    """Enable multiplex."""
    protocol: Literal["smux", "yamux", "h2mux"] | None = None
    """
    Multiplex protocol.

    | Protocol | Description                        |
    | -------- | ---------------------------------- |
    | smux     | https://github.com/xtaci/smux      |
    | yamux    | https://github.com/hashicorp/yamux |
    | h2mux    | https://golang.org/x/net/http2     |

    `h2mux` is used by default.
    """
    max_connections: int | None = None
    """Max connections. Conflict with `max_streams`."""
    min_streams: int | None = None
    """
    Minimum multiplexed streams in a connection before opening a new connection.

    Conflict with `max_streams`.
    """
    max_streams: int | None = None
    """
    Maximum multiplexed streams in a connection before opening a new connection.

    Conflict with `max_connections` and `min_streams`.
    """
    padding: bool | None = None
    """Enable padding for each stream."""
    brutal: dict | None = None
    """See TCP Brutal for details."""


@define
class BaseTransport:
    type: TransportType


@define
class PlatformHttpProxy:
    server: ServerAddress
    """**Required** HTTP proxy server address."""
    server_port: int
    """**Required** HTTP proxy server port."""
    enabled: bool | None = None
    """Enable system HTTP proxy."""
    bypass_domain: Sequence[str] | None = None
    """
    > ![WARNING]
    > On Apple platforms, `bypass_domain` items matches hostname **suffixes**.

    Hostnames that bypass the HTTP proxy.
    """
    match_domain: Sequence[str] | None = None
    """
    > ![WARNING]
    > Only supported in graphical clients on Apple platforms.

    Hostnames that use the HTTP proxy.
    """


@define
class Platform:
    http_proxy: PlatformHttpProxy
    """System HTTP proxy settings."""
