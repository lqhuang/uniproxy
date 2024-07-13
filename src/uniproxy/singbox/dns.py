from __future__ import annotations

from typing import Literal

from enum import StrEnum

from attrs import frozen

from .base import BaseInbound, BaseOutbound
from .shared import SniffProtocol

DnsReturnCode = Literal[
    "rcode://success",
    "rcode://format_error",
    "rcode://server_failure",
    "rcode://name_error",
    "rcode://not_implemented",
    "rcode://refused",
]


class DnsReturnCodeEnum(StrEnum):
    SUCCESS = "rcode://success"
    FORMAT_ERROR = "rcode://format_error"
    SERVER_FAILURE = "rcode://server_failure"
    NAME_ERROR = "rcode://name_error"
    NOT_IMPLEMENTED = "rcode://not_implemented"
    REFUSED = "rcode://refused"


DnsStrategy = Literal["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only", "", None]


class DnsStrategyEnum(StrEnum):
    PREFER_IPV4 = "prefer_ipv4"
    PREFER_IPV6 = "prefer_ipv6"
    IPV4_ONLY = "ipv4_only"
    IPV6_ONLY = "ipv6_only"


@frozen
class DNS:
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/
    """

    servers: list[DnsServer] | None
    rules: list[DnsRule] | None

    # Default dns server tag. The first server will be used if empty.
    final: str | None = None

    # Default domain strategy for resolving the domain names.
    # One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    # Take no effect if `server.strategy` is set.
    strategy: DnsStrategy = None

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
    fakeip: FakeIP | None = None

    # > Since `sing-box`  1.9.0
    #
    # Append a `edns0-subnet`` OPT extra record with the specified IP address to every query by default.
    #
    # Can be overrides by `servers.[].client_subnet`` or `rules.[].client_subnet`.
    client_subnet: str | None = None


@frozen
class DnsServer:
    tag: str
    address: str | DnsReturnCode | Literal["local", "dhcp://auto", "fakeip"]

    # Required if address contains domain
    #
    # Tag of a another server to resolve the domain name in the address.
    address_resolver: str | DnsServer | None = None

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
    detour: str | None = None

    client_subnet: str | None = None

    def __str__(self) -> str:
        return str(self.tag)


@frozen
class DnsRule:
    server: str
    outbound: list[BaseOutbound] | list[str] | Literal["any"] | None = None
    inbound: list[BaseInbound] | list[str] | None = None
    ip_version: Literal["4", "6", None] = None
    auth_user: str | None = None
    protocol: SniffProtocol | None = None
    network: str | None = None
    domain: str | None = None
    domain_suffix: str | None = None
    domain_keyword: str | None = None
    domain_regex: str | None = None
    ip_cidr: list[str] | None = None
    ip_is_private: bool | None = None
    source_ip_cidr: list[str] | None = None
    source_ip_is_private: bool | None = None
    source_port: int | None = None
    source_port_range: list[str] | None = None
    port: list[int] | None = None
    port_range: list[str] | None = None
    rule_set: list[str] | None = None
    rule_set_ipcidr_match_source: bool | None = None
    invert: bool | None = None


@frozen
class FakeIP:
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/fakeip/

    ```json
    {
      "enabled": true,
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    }
    ```
    """

    enabled: bool | None = None
    inet4_range: str | None = None
    inet6_range: str | None = None
