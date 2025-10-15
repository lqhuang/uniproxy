from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import NetworkCIDR

from attrs import define, field

from uniproxy.abc import AbstractSingBox
from uniproxy.utils import maybe_flatmap_to_str, maybe_to_str

from .base import BaseDnsServer, BaseInbound, BaseOutbound
from .route import BaseRuleSet
from .shared import DialFieldsMixin, OutboundTLS
from .typing import DnsReturnCode, DnsStrategy, SniffProtocol


@define
class DNS(AbstractSingBox):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/
    """

    servers: Sequence[BaseDnsServer] | None
    rules: Sequence[DnsRule] | None = None

    # Default dns server tag. The first server will be used if empty.
    final: str | BaseDnsServer | None = field(default=None, converter=maybe_to_str)

    # Default domain strategy for resolving the domain names.
    # One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    # Take no effect if `server.strategy` is set.
    strategy: DnsStrategy | None = None

    # Disable dns cache.
    disable_cache: bool | None = None

    # Disable dns cache expire.
    disable_expire: bool | None = None

    # Make each DNS server's cache independent for special purposes.
    # If enabled, will slightly degrade performance.
    independent_cache: bool | None = None

    # Stores a reverse mapping of IP addresses after responding to a DNS query
    # in order to provide domain names when routing.
    #
    # Since this process relies on the act of resolving domain names by
    # an application before making a request, it can be problematic in
    # environments such as macOS, where DNS is proxied and cached by
    # the system.
    reverse_mapping: bool | None = None

    # FakeIP settings.
    # @deprecated since 1.12.0, use `FakeIPDnsServer` instead.
    # fakeip: FakeIP | None = None

    # > Since `sing-box`  1.9.0
    #
    # Append a `edns0-subnet`` OPT extra record with the specified IP address to every query by default.
    #
    # Can be overrides by `servers.[].client_subnet`` or `rules.[].client_subnet`.
    client_subnet: str | None = None

    cache_capacity: int = 4096


@define
class LegacyDnsServer(BaseDnsServer):
    # Deprecate since 1.11.0, remove in 1.13.0
    address: str | DnsReturnCode | Literal["local", "dhcp://auto", "fakeip"]

    # Required if address contains domain
    #
    # Tag of a another server to resolve the domain name in the address.
    address_resolver: BaseDnsServer | str | None = field(
        default=None, converter=maybe_to_str
    )

    # The domain strategy for resolving the domain name in the address.
    # One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    # `dns.strategy` will be used if empty.
    address_strategy: str | None = None

    # Default domain strategy for resolving the domain names.
    # One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    # Take no effect if overridden by other settings.
    strategy: DnsStrategy | None = None

    # Tag of an outbound for connecting to the dns server.
    #
    # Default outbound will be used if empty.
    detour: BaseOutbound | str | None = field(default=None, converter=maybe_to_str)

    client_subnet: str | None = None


@define
class LocalDnsServer(BaseDnsServer):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/server/local/

    ```json
    {
      "type": "local",
      "tag": "",
      // Dial Fields
    }
    ```
    """

    type: Literal["local"] = "local"


@define(slots=False)
class BaseUdp(BaseDnsServer):
    server: str
    server_port: int | None = None


@define
class UdpDnsServer(DialFieldsMixin, BaseUdp):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/server/udp/

    ```json
    {
        "type": "udp",
        "tag": "",

        "server": "",
        "server_port": 53,

        // Dial Fields
    }
    ```
    """

    type: Literal["udp"] = "udp"


@define(slots=False)
class BaseTls(BaseDnsServer):
    server: str
    server_port: int | None = None
    tls: OutboundTLS | None = None


@define
class TlsDnsServer(DialFieldsMixin, BaseTls):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/server/udp/

    ```json
    {
        "type": "udp",
        "tag": "",

        "server": "",
        "server_port": 853,

        "tls": {},

        // Dial Fields
    }
    ```
    """

    type: Literal["tls"] = "tls"


@define(slots=False)
class BaseQuic(BaseDnsServer):
    server: str
    server_port: int | None = None
    tls: OutboundTLS | None = None


@define
class QuicDnsServer(BaseDnsServer):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/server/quic/

    ```json
    {
        "type": "quic",
        "tag": "",

        "server": "",
        "server_port": 853,

        "tls": {},

        // Dial Fields
    }
    ```
    """

    type: Literal["quic"] = "quic"


@define(slots=False)
class BaseHttps(BaseDnsServer):
    server: str
    server_port: int | None = None
    path: str | None = None
    headers: dict[str, str] | None = None
    tls: OutboundTLS | None = None


@define
class HttpsDnsServer(DialFieldsMixin, BaseHttps):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/server/https/

    ```json
    {
        "type": "https",
        "tag": "",

        "server": "",
        "server_port": 443,

        "path": "",
        "headers": {},

        "tls": {},

        // Dial Fields
    }
    ```
    """

    type: Literal["https"] = "https"


@define(slots=False)
class BaseH3(BaseDnsServer):
    server: str
    server_port: int | None = None
    path: str | None = None
    headers: dict[str, str] | None = None
    tls: OutboundTLS | None = None


@define
class H3DnsServer(DialFieldsMixin, BaseH3):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/server/http3/

    ```json
    {
        "type": "h3",
        "tag": "",

        "server": "",
        "server_port": 443,

        "path": "",
        "headers": {},

        "tls": {},

        // Dial Fields
    }
    ```
    """

    type: Literal["h3"] = "h3"


@define
class FakeIPDnsServer(BaseDnsServer):
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/server/fakeip/

    ```json
    {
      "dns": {
        "servers": [
          {
            "type": "fakeip",
            "tag": "",

            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18"
          }
        ]
      }
    }
    ```
    """

    inet4_range: str | None = None
    inet6_range: str | None = None
    type: Literal["fakeip"] = "fakeip"


type DnsServer = (
    LocalDnsServer
    | UdpDnsServer
    | TlsDnsServer
    | QuicDnsServer
    | HttpsDnsServer
    | H3DnsServer
    | FakeIPDnsServer
    | LegacyDnsServer
)


type DnsRuleAction = Literal["route", "route-options", "reject", "predefined", "fakeip"]


@define
class DnsRule(AbstractSingBox):
    server: str | BaseDnsServer = field(converter=str)
    action: DnsRuleAction | None = None
    strategy: DnsStrategy | None = None
    client_subnet: str | None = None

    # outbound: Sequence[BaseOutbound] | Sequence[str] | Literal["any"] | None = None

    inbound: Sequence[BaseInbound | str] | None = field(
        default=None, converter=maybe_flatmap_to_str
    )
    ip_version: Literal["4", "6", None] = None
    auth_user: str | None = None
    protocol: SniffProtocol | None = None
    network: str | None = None
    domain: str | None = None
    domain_suffix: str | Sequence[str] | None = None
    domain_keyword: str | Sequence[str] | None = None
    domain_regex: str | Sequence[str] | None = None
    ip_cidr: str | NetworkCIDR | Sequence[NetworkCIDR | str] | None = None
    ip_is_private: bool | None = None
    source_ip_cidr: Sequence[NetworkCIDR] | None = None
    source_ip_is_private: bool | None = None
    source_port: int | None = None
    source_port_range: Sequence[str] | None = None
    port: Sequence[int] | None = None
    port_range: Sequence[str] | None = None
    rule_set: Sequence[str | BaseRuleSet] | str | BaseRuleSet | None = field(
        default=None, converter=maybe_flatmap_to_str
    )
    rule_set_ip_cidr_match_source: bool | None = None
    rule_set_ip_cidr_accept_empty: bool | None = None
    invert: bool | None = None
