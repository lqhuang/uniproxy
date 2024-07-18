from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import ServerAddress

from ipaddress import IPv4Address, IPv6Address
from os import PathLike

from attrs import define

from uniproxy.protocols import TLS as UniproxyTLS

from .base import BaseInbound, BaseOutbound
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


@define
class BaseTLS:
    enabled: bool | None = None
    server_name: str | None = None


@define
class InboundTLS(BaseTLS):
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
    disable_sni: bool | None = None
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


@define(slots=False)
class ListenFieldsMixin:
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


@define(slots=False)
class DialFieldsMixin:
    """
    ```json
    {
      "detour": "upstream-out",
      "bind_interface": "en0",
      "inet4_bind_address": "0.0.0.0",
      "inet6_bind_address": "::",
      "routing_mark": 1234,
      "reuse_addr": false,
      "connect_timeout": "5s",
      "tcp_fast_open": false,
      "tcp_multi_path": false,
      "udp_fragment": false,
      "domain_strategy": "prefer_ipv6",
      "fallback_delay": "300ms"
    }
    ```

    - bind_interface
    - bind_address
    - routing_mark
    - reuse_addr
    - tcp_fast_open
    - tcp_multi_path
    - udp_fragment
    - connect_timeout
    """

    detour: BaseOutbound | str | None = None
    """The tag of the upstream outbound."""
    bind_interface: str | None = None
    """The network interface to bind to."""
    inet4_bind_address: str | IPv4Address | None = None
    """The IPv4 address to bind to."""
    inet6_bind_address: str | IPv6Address | None = None
    """The IPv6 address to bind to."""
    routing_mark: str | None = None
    """
    > ![NOTE]
    > Only supported on Linux.

    Set netfilter routing mark.
    """
    reuse_addr: bool | None = None
    """Reuse listener address."""
    tcp_fast_open: bool | None = None
    """Enable TCP Fast Open."""
    tcp_multi_path: bool | None = None
    """Enable TCP Multi Path."""
    udp_fragment: bool | None = None
    """Enable UDP fragmentation."""
    connect_timeout: str | None = None
    """
    Connect timeout, in golang's Duration format.

    A duration string is a possibly signed sequence of decimal numbers,
    each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
    Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
    """
    domain_strategy: DnsStrategy | None = None
    """
    One of prefer_ipv4 prefer_ipv6 ipv4_only ipv6_only.

    If set, the requested domain name will be resolved to IP before connect.

    | Outbound | Effected domains         | Fallback Value                          |
    | -------- | ------------------------ | --------------------------------------- |
    | direct   | Domain in request        | Take inbound.domain_strategy if not set |
    | others   | Domain in server address | /                                       |
    """
    fallback_delay: str | None = None
    """
    The length of time to wait before spawning a RFC 6555 Fast Fallback connection.
    That is, is the amount of time to wait for connection to succeed before assuming
    that IPv4/IPv6 is misconfigured and falling back to other type of addresses.
    If zero, a default delay of 300ms is used.

    Only take effect when `domain_strategy` is set.
    """

    def __attrs_post_init__(self):
        if hasattr(super(), "__attrs_post_init__"):
            super().__attrs_post_init__()
        if self.detour and self.bind_interface:
            raise ValueError("'detour' and 'bind_interface' are mutually exclusive.")


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
    > ![WARN]
    > On Apple platforms, `bypass_domain` items matches hostname **suffixes**.

    Hostnames that bypass the HTTP proxy.
    """
    match_domain: Sequence[str] | None = None
    """
    > ![WARN]
    > Only supported in graphical clients on Apple platforms.

    Hostnames that use the HTTP proxy.
    """


@define
class Platform:
    http_proxy: PlatformHttpProxy
    """System HTTP proxy settings."""
