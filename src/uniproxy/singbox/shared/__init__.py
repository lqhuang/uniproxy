from __future__ import annotations

from typing import TYPE_CHECKING, Literal, Sequence, TypedDict
from uniproxy.typing import AlpnType, ServerAddress

from ipaddress import IPv4Address, IPv6Address

from attrs import define, field

from uniproxy.utils import maybe_to_tag, to_tag

from ..base import AbstractSingBox, BaseDnsServer, BaseInbound, BaseOutbound
from ..typing import TransportType
from .tls import *  # noqa: F403

if TYPE_CHECKING:
    from ..dns import DnsStrategy


@define(slots=False)
class ListenableMixin:
    listen: str
    listen_port: int


@define(slots=False)
class ListenFieldsMixin:
    tcp_fast_open: bool | None = None
    """Enable TCP Fast Open."""

    tcp_multi_path: bool | None = None
    """Enable TCP Multi Path."""

    udp_fragment: bool | None = None
    """Enable UDP fragmentation."""

    udp_timeout: str | None = None
    """
    UDP NAT expiration time in seconds.

    `5m` is used by default.
    """

    detour: BaseInbound | str | None = field(default=None, converter=maybe_to_tag)
    """
    If set, connections will be forwarded to the specified inbound.

    Requires target inbound support, see Injectable.
    """

    # sniff: bool | None = None
    # """Enable sniffing."""

    # sniff_override_destination: bool | None = None
    # """
    # Override the connection destination address with the sniffed domain.

    # If the domain name is invalid (like tor), this will not work.
    # """

    # sniff_timeout: str | None = None
    # """
    # Timeout for sniffing.

    # 300ms is used by default.
    # """

    # domain_strategy: DnsStrategy | None = None
    # """
    # One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.

    # If set, the requested domain name will be resolved to IP before routing.

    # If `sniff_override_destination` is in effect, its value will be taken as a fallback.
    # """

    # udp_disable_domain_unmapping: bool | None = None
    # """
    # If enabled, for UDP proxy requests addressed to a domain, the original
    # packet address will be sent in the response instead of the mapped domain.

    # This option is used for compatibility with clients that do not support
    # receiving UDP packets with domain addresses, such as Surge.
    # """


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
    -bind_interface
    -bind_address
    -routing_mark
    -reuse_addr
    -tcp_fast_open
    -tcp_multi_path
    -udp_fragment
    -connect_timeout"""

    detour: BaseOutbound | str | None = field(default=None, converter=maybe_to_tag)
    """The tag of the upstream outbound."""

    bind_interface: str | None = None
    """The network interface to bind to."""

    inet4_bind_address: str | IPv4Address | None = None
    """The IPv4 address to bind to."""

    inet6_bind_address: str | IPv6Address | None = None
    """The IPv6 address to bind to."""

    routing_mark: str | None = None
    """
    > [!NOTE]
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

    # domain_strategy: DnsStrategy | None = None
    # """
    # One of prefer_ipv4 prefer_ipv6 ipv4_only ipv6_only.

    # If set, the requested domain name will be resolved to IP before connect.

    # | Outbound | Effected domains         | Fallback Value                          |
    # | -------- | ------------------------ | --------------------------------------- |
    # | direct   | Domain in request        | Take inbound.domain_strategy if not set |
    # | others   | Domain in server address | /                                       |
    # """

    domain_resolver: DomainResolver | DomainResolverMap | str | None = field(
        default=None, converter=maybe_to_tag
    )
    """
    Set domain resolver to use for resolving domain names.

    This option uses the same format as the [route DNS rule action](https://sing-box.sagernet.org/configuration/dns/rule_action/#route) without the `action` field.

    Setting this option directly to a string is equivalent to setting `server` of this options.

    | Outbound/Endpoints | Effected domains
    | :----------------- | ---------------------------------------
    | `direct`           | Domain in request
    | others             | Domain in server address
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
        if self.detour and self.bind_interface:
            raise ValueError("'detour' and 'bind_interface' are mutually exclusive.")


@define(slots=False)
class InboundMultiplex:
    enabled: bool | None = None
    padding: bool | None = None
    # brutal: dict | None = None


@define(slots=False)
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

    # pyrefly: ignore [implicit-any-type-argument]
    brutal: dict | None = None
    """See TCP Brutal for details."""


@define(slots=False)
class BaseTransport(AbstractSingBox):
    type: TransportType


@define
class PlatformHttpProxy(AbstractSingBox):
    server: ServerAddress
    """HTTP proxy server address."""

    server_port: int
    """HTTP proxy server port."""

    enabled: bool | None = None
    """Enable system HTTP proxy."""

    bypass_domain: Sequence[str] | None = None
    """
    > [!WARN]
    >
    > On Apple platforms, `bypass_domain` items matches hostname **suffixes**.

    Hostnames that bypass the HTTP proxy.
    """

    match_domain: Sequence[str] | None = None
    """
    > [!WARN]
    > Only supported in graphical clients on Apple platforms.

    Hostnames that use the HTTP proxy.
    """


@define
class Platform(AbstractSingBox):
    http_proxy: PlatformHttpProxy
    """System HTTP proxy settings."""


@define
class DomainResolver(AbstractSingBox):
    """
    Set domain resolver to use for resolving domain names.

    This option uses the same format as the [route DNS rule action](https://sing-box.sagernet.org/configuration/dns/rule_action/#route) without the `action` field.

    ```json
    {
        "server": "",
        "strategy": "",
        "disable_cache": false,
        "rewrite_ttl": null,
        "client_subnet": null
    }
    ```

    Setting this option directly to a string is equivalent to setting `server` of this options.


    | Outbound/Endpoints | Effected domains         |
    | ------------------ | ------------------------ |
    | `direct`           | Domain in request        |
    | others             | Domain in server address |
    """

    server: BaseDnsServer | str = field(converter=to_tag)
    """Tag of target server."""

    strategy: DnsStrategy | None = None
    """
    Set domain strategy for this query.

    One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    """

    disable_cache: bool | None = None
    """Disable cache and save cache in this query."""

    rewrite_ttl: bool | None = None
    """Rewrite TTL in DNS responses."""

    client_subnet: str | None = None
    """
    Append a `edns0-subnet` OPT extra record with the specified IP prefix to every query by default.

    If value is an IP address instead of prefix, `/32` or `/128` will be appended automatically.

    Will overrides `dns.client_subnet`.
    """


class DomainResolverMap(TypedDict):
    """
    Set domain resolver to use for resolving domain names.

    This option uses the same format as the [route DNS rule action](https://sing-box.sagernet.org/configuration/dns/rule_action/#route) without the `action` field.

    ```json
    {
        "server": "",
        "strategy": "",
        "disable_cache": false,
        "rewrite_ttl": null,
        "client_subnet": null
    }
    ```

    Setting this option directly to a string is equivalent to setting `server` of this options.


    | Outbound/Endpoints | Effected domains         |
    | ------------------ | ------------------------ |
    | `direct`           | Domain in request        |
    | others             | Domain in server address |
    """

    server: str
    """Tag of target server."""

    strategy: DnsStrategy | None
    """
    Set domain strategy for this query.

    One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    """

    disable_cache: bool | None
    """Disable cache and save cache in this query."""

    rewrite_ttl: bool | None
    """Rewrite TTL in DNS responses."""

    client_subnet: str | None
    """
    Append a `edns0-subnet` OPT extra record with the specified IP prefix to every query by default.

    If value is an IP address instead of prefix, `/32` or `/128` will be appended automatically.

    Will overrides `dns.client_subnet`.
    """


class UdpOverTcp(TypedDict):
    """
    References:

    - https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/
    """

    enabled: bool | None
    """Enable the UDP over TCP protocol."""
    version: Literal[1, 2] | None
    """The protocol version, `1` or `2`. Version `2` is used by default."""
