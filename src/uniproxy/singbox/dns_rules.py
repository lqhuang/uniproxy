from __future__ import annotations

from typing import Iterable, Literal, Sequence
from uniproxy.typing import NetworkCIDR

from attrs import define, field

from uniproxy.utils import maybe_flatmap_to_str

from .base import BaseDnsRule, BaseDnsServer, BaseInbound
from .typing import SniffProtocol

type DnsRuleAction = Literal[
    "route", "evaluate", "respond", "route-options", "reject", "predefined"
]
type DnsPreferredBy = Literal["hosts", "local", "mdns", "tailscale", "resolved"]


@define(slots=False)
class _DnsRuleMixin:
    inbound: Sequence[BaseInbound | str] | None = field(
        default=None, converter=maybe_flatmap_to_str
    )
    """
    Tags of Inbound
    """

    ip_version: Literal[4, 6, None] = None
    """

    """

    query_type: Sequence[Literal["A", "AAAA", "CNAME", "DNSKEY"] | str] | None = None
    """
    https://en.wikipedia.org/wiki/List_of_DNS_record_types
    """

    network: Literal["tcp", "udp"] | None = None

    auth_user: str | None = None
    """
    Username, see each inbound for details.
    """

    protocol: SniffProtocol | None = None
    """
    Sniffed protocol, see Sniff for details.
    """

    domain: str | Iterable[str] | None = None
    domain_suffix: str | Iterable[str] | None = None
    domain_keyword: str | Iterable[str] | None = None
    domain_regex: str | Iterable[str] | None = None

    source_ip_cidr: Iterable[NetworkCIDR] | None = None
    source_ip_is_private: bool | None = None
    source_port: int | Iterable[int] | None = None
    source_port_range: Iterable[str] | None = None

    port: Iterable[int] | None = None
    port_range: Iterable[str] | None = None

    package_name: str | Iterable[str] | None = None
    package_name_regex: str | Iterable[str] | None = None

    preferred_by: DnsPreferredBy | Iterable[DnsPreferredBy] | None = None
    """
    The tag of a rule or server that is preferred when multiple rules match.
    """

    rule_set: tuple[str, ...] | str | None = field(
        default=None, converter=maybe_flatmap_to_str
    )
    rule_set_ip_cidr_match_source: bool | None = None

    match_response: bool | None = None
    ip_accept_any: bool | None = None
    invert: bool | None = None


@define(slots=False)
class _BaseDnsRouteRule(BaseDnsRule):
    server: str | BaseDnsServer = field(converter=str)
    """
    Tag of target server.
    """

    disable_cache: bool | None = None
    """
    Disable dns cache.
    """

    disable_optimistic_cache: bool | None = None
    """
    Disable optimistic DNS caching in this query.
    """

    rewrite_ttl: str | None = None

    timeout: str | None = None

    client_subnet: str | None = None
    """
    Append a `edns0-subnet` OPT extra record with the specified IP address to every query by default.

    If value is an IP address instead of prefix, `/32` or `/128` will be appended automatically.

    Will override `dns.client_subnet`.
    """


@define
class DnsRouteRule(_DnsRuleMixin, _BaseDnsRouteRule, BaseDnsRule):
    action: Literal["route"] | None = None


@define(slots=False)
class _BaseDnsRejectRule(BaseDnsRule):
    method: Literal["default", "drop"] | None = None
    no_drop: bool | None = None


@define
class DnsRejectRule(_DnsRuleMixin, _BaseDnsRejectRule):
    action: Literal["reject"] = "reject"


type DnsRule = DnsRouteRule | DnsRejectRule
