from __future__ import annotations

from typing import Literal, Sequence, TypedDict
from uniproxy.typing import AlpnType, ServerAddress

from ipaddress import IPv4Address, IPv6Address
from os import PathLike

from attrs import define, field

from uniproxy.abc import AbstractSingBox
from uniproxy.protocols import TLS as UniproxyTLS

from .base import BaseDnsServer, BaseInbound, BaseOutbound
from .typing import DnsStrategy, TLSVersion, TransportType


@define
class Fallback(AbstractSingBox):
    server: ServerAddress
    server_port: int


@define
class ExternalAccount(AbstractSingBox):
    key_id: str | None = None
    """The key identifier."""
    mac_key: str | None = None
    """The MAC key."""


@define
class CloudflareDNS01Challenge(AbstractSingBox):
    api_token: str
    provider: Literal["cloudflare"] = "cloudflare"


@define
class AliDNS01Challenge(AbstractSingBox):
    access_key_id: str
    access_key_secret: str
    region_id: str
    provider: Literal["alidns"] = "alidns"


type DNS01Challenge = CloudflareDNS01Challenge | AliDNS01Challenge


@define
class ACME(AbstractSingBox):
    domain: Sequence[str] | None = None
    """
    List of domain.

    ACME will be disabled if empty.
    """

    data_directory: str | None = None
    """
    The directory to store ACME data.

    `$XDG_DATA_HOME/certmagic|$HOME/.local/share/certmagic` will be used if empty.
    """

    default_server_name: str | None = None
    """Server name to use when choosing a certificate if the ClientHello's ServerName field is empty."""

    email: str | None = None
    """The email address to use when creating or selecting an existing ACME server account"""

    provider: Literal["letsencrypt", "zerossl"] | str | None = None
    """
    The ACME CA provider to use.

    | Value                      | Provider       |
    |----------------------------|----------------|
    | `letsencrypt (default)`    | Let's Encrypt  |
    | `zerossl`                  | ZeroSSL        |
    | `https://...`              | Custom         |
    """

    disable_http_challenge: bool | None = None
    """Disable all HTTP challenges."""

    disable_tls_alpn_challenge: bool | None = None
    """Disable all TLS-ALPN challenges."""

    alternative_http_port: int | None = None
    """
    The alternate port to use for the ACME HTTP challenge;
    if non-empty, this port will be used instead of 80 to spin up
    a listener for the HTTP challenge.
    """

    alternative_tls_port: int | None = None
    """
    The alternate port to use for the ACME TLS-ALPN challenge;
    the system must forward 443 to this port for challenge to succeed.
    """

    external_account: ExternalAccount | None = None
    """
    EAB (External Account Binding) contains information necessary to bind or
    map an ACME account to some other account known by the CA.

    External account bindings are "used to associate an ACME account with an
    existing account in a non-ACME system, such as a CA customer database.

    To enable ACME account binding, the CA operating the ACME server needs to
    provide the ACME client with a MAC key and a key identifier, using some
    mechanism outside of ACME.
    """

    dns01_challenge: DNS01Challenge | None = None
    """ACME DNS01 challenge field. If configured, other challenge methods will be disabled."""


@define
class ECH(AbstractSingBox):
    enabled: bool | None = None
    pq_signature_schemes_enabled: bool | None = None
    dynamic_record_sizing_disabled: bool | None = None
    key: Sequence[str] | None = None
    key_path: str | None = None


@define
class UTLS(AbstractSingBox):
    enabled: bool | None = None
    fingerprint: str | None = None


@define(slots=False)
class BaseTLS(AbstractSingBox):
    enabled: bool
    """Enable TLS."""

    server_name: str | None = None
    """
    Used to verify the hostname on the returned certificates unless insecure is given.

    It is also included in the client's handshake to support virtual hosting unless it is an IP address.
    """

    alpn: Sequence[AlpnType] | None = None
    """
    List of supported application level protocols, in order of preference.

    If both peers support ALPN, the selected protocol will be one from this list,
    and the connection will fail if there is no mutually supported protocol.

    See [Application-Layer Protocol Negotiation](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).
    """

    min_version: TLSVersion | None = None
    """
    The minimum TLS version that is acceptable.

    By default, TLS 1.2 is currently used as the minimum when acting as a
    client, and TLS 1.0 when acting as a server.
    """

    max_version: TLSVersion | None = None
    """
    The maximum TLS version that is acceptable.

    By default, the maximum version is currently TLS 1.3.
    """

    cipher_suites: Sequence[str] | None = None
    """
    A list of enabled TLS 1.0–1.2 cipher suites. The order of the list is
    ignored. Note that TLS 1.3 cipher suites are not configurable.

    If empty, a safe default list is used. The default cipher suites might change over time.
    """

    certificate: Sequence[str] | None = None
    """The server certificate line array, in PEM format."""
    certificate_path: PathLike | None = None
    """
    > [!NOTE]
    >
    >  Will be automatically reloaded if file modified.

    The path to the server certificate, in PEM format.
    """


@define
class InboundTLS(BaseTLS):
    key: Sequence[str] | None = None
    """The server private key line array, in PEM format."""

    key_path: PathLike | None = None
    """
    > [!NOTE]
    >
    >  Will be automatically reloaded if file modified.

    The path to the server certificate, in PEM format.
    """

    acme: ACME | None = None

    ech: ECH | None = None


@define
class OutboundTLS(BaseTLS):
    disable_sni: bool | None = None
    """Do not send server name in ClientHello."""

    insecure: bool | None = None
    """Accepts any server certificate."""

    utls: UTLS | None = None

    ech: ECH | None = None

    @classmethod
    def from_uniproxy(cls, tls: UniproxyTLS, **kwargs) -> OutboundTLS:
        return cls(
            enabled=tls is not None,
            disable_sni=not tls.sni,
            server_name=tls.server_name,
            insecure=not tls.verify,
            alpn=tls.alpn,
        )


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

    detour: BaseInbound | str | None = None
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
        default=None, converter=lambda x: str(x) if x is not None else None
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

    server: BaseDnsServer | str = field(converter=str)
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
