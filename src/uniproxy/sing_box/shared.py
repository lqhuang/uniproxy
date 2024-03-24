from __future__ import annotations

from typing import Literal

from abc import ABC
from enum import StrEnum
from os import PathLike

from attrs import frozen

from uniproxy.protocols.std import TLS as UniproxyTLS

from .base import BaseInbound
from .dns import DnsStrategy

SniffProtocol = Literal["HTTP", "TLS", "QUIC", "STUN", "DNS"]


class SniffProtocolEnum(StrEnum):
    HTTP = "HTTP"
    TLS = "TLS"
    QUIC = "QUIC"
    STUN = "STUN"
    DNS = "DNS"


@frozen
class ExternalAccount:
    key_id: str | None = None
    mac_key: str | None = None


@frozen
class DNS01Challenge:
    provider: Literal["cloudflare", "alidns"]


@frozen
class CloudflareDNS01Challenge(DNS01Challenge):
    provider: Literal["cloudflare"]
    api_token: str


@frozen
class AliDNS01Challenge(DNS01Challenge):
    provider: Literal["alidns"]
    access_key_id: str
    access_key_secret: str
    region_id: str


@frozen
class ACME:
    domain: list[str] | None = None
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


@frozen
class ECH:
    enabled: bool | None = None
    pq_signature_schemes_enabled: bool | None = None
    dynamic_record_sizing_disabled: bool | None = None
    key: list[str] | None = None
    key_path: str | None = None


@frozen
class UTLS:
    enabled: bool | None = None
    fingerprint: str | None = None


class BaseTLS(ABC): ...


@frozen
class InboundTLS:
    enabled: bool | None = None
    server_name: str | None = None
    alpn: list[str] | None = None
    min_version: str | None = None
    max_version: str | None = None
    cipher_suites: list[str] | None = None
    certificate: list[str] | None = None
    certificate_path: PathLike | None = None
    key: list[str] | None = None
    key_path: PathLike | None = None
    acme: ACME | None = None
    ech: ECH | None = None


@frozen
class OutboundTLS(BaseTLS):
    enabled: bool | None = None
    disable_sni: bool | None = None
    server_name: str | None = None
    insecure: bool | None = None
    alpn: list[str] | None = None
    min_version: str | None = None
    max_version: str | None = None
    cipher_suites: list[str] | None = None
    certificate: list[str] | None = None
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


@frozen
class DialFields: ...


class MixinListenFields:
    listen: str
    listen_port: int | None = None
    tcp_fast_open: bool | None = None
    tcp_multi_path: bool | None = None
    udp_fragment: bool | None = None

    # UDP NAT expiration time in seconds.
    #
    # `5m` is used by default.
    udp_timeout: str | None = None

    # If set, connections will be forwarded to the specified inbound.
    #
    # Requires target inbound support, see Injectable.
    detour: BaseInbound | str | None = None

    sniff: bool | None = None
    sniff_override_destination: bool | None = None
    sniff_timeout: str | None = None

    # One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    #
    # If set, the requested domain name will be resolved to IP before routing.
    #
    # If `sniff_override_destination` is in effect, its value will be taken as a fallback.
    domain_strategy: DnsStrategy | None = None

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

    # Enable multiplex.
    enabled: bool | None = None
    # Multiplex protocol.
    #
    # | Protocol | Description                        |
    # | -------- | ---------------------------------- |
    # | smux     | https://github.com/xtaci/smux      |
    # | yamux    | https://github.com/hashicorp/yamux |
    # | h2mux    | https://golang.org/x/net/http2     |
    #
    # `h2mux` is used by default.
    protocol: Literal["smux", "yamux", "h2mux"] | None = None
    # Max connections. Conflict with `max_streams`.
    max_connections: int | None = None
    # Minimum multiplexed streams in a connection before opening a new connection.
    # Conflict with `max_streams`.
    min_streams: int | None = None
    # Maximum multiplexed streams in a connection before opening a new connection.
    # Conflict with `max_connections` and `min_streams`.
    max_streams: int | None = None
    # Enable padding for each stream.
    padding: bool | None = None
    # # See TCP Brutal for details.
    # brutal: dict | None = None


TransportType = Literal["http", "ws", "quic", "grpc", "httpupgrade"]


class TransportTypeEnum(StrEnum):
    HTTP = "http"
    WS = "ws"
    QUIC = "quic"
    GRPC = "grpc"
    HTTP_UPGRADE = "httpupgrade"


@frozen
class BaseTransport:
    type: TransportType
