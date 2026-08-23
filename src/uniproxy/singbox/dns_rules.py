from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import NetworkCIDR

from attrs import define, field

from uniproxy.utils import maybe_map_to_tag, to_tag

from .base import BaseDnsRule, BaseDnsServer, BaseInbound
from .typing import NetworkConn, NetworkProtocol, SniffProtocol

type DnsRuleAction = Literal[
    "route", "evaluate", "respond", "route-options", "reject", "predefined"
]
type DnsPreferredBy = Literal["hosts", "local", "mdns", "tailscale", "resolved"]


@define(slots=False)
class _DnsRuleMixin:
    inbound: Sequence[BaseInbound | str] | None = field(
        default=None, converter=maybe_map_to_tag
    )
    """
    Tags of Inbound
    """

    ip_version: Literal[4, 6, None] = None
    """

    """

    query_type: Sequence[Literal["A", "AAAA", "CNAME", "DNSKEY"] | str | int] | None = (
        None
    )
    """
    https://en.wikipedia.org/wiki/List_of_DNS_record_types
    """

    query_client_subnet: str | Sequence[str] | None = None

    query_dnssec: bool | None = None

    network: NetworkProtocol | Sequence[NetworkProtocol] | None = None

    auth_user: str | Sequence[str] | None = None
    """
    Username, see each inbound for details.
    """

    protocol: SniffProtocol | Sequence[SniffProtocol] | None = None
    """
    Sniffed protocol, see Sniff for details.
    """

    domain: str | Sequence[str] | None = None
    domain_suffix: str | Sequence[str] | None = None
    domain_keyword: str | Sequence[str] | None = None
    domain_regex: str | Sequence[str] | None = None

    source_ip_cidr: Sequence[NetworkCIDR] | None = None
    source_ip_is_private: bool | None = None
    source_port: int | Sequence[int] | None = None
    source_port_range: Sequence[str] | None = None
    port: Sequence[int] | None = None
    port_range: Sequence[str] | None = None

    process_name: str | Sequence[str] | None = None
    process_path: str | Sequence[str] | None = None
    process_path_regex: str | Sequence[str] | None = None
    package_name: str | Sequence[str] | None = None
    package_name_regex: str | Sequence[str] | None = None

    user: str | Sequence[str] | None = None
    user_id: int | Sequence[int] | None = None

    network_type: NetworkConn | Sequence[NetworkConn] | None = None
    network_is_expensive: bool | None = None
    network_is_constrained: bool | None = None
    interface_address: None = None
    network_interface_address: None = None
    default_interface_address: None = None

    source_mac_address: str | Sequence[str] | None = None
    source_hostname: str | Sequence[str] | None = None

    preferred_by: DnsPreferredBy | Sequence[DnsPreferredBy] | None = None
    """
    The tag of a rule or server that is preferred when multiple rules match.
    """

    wifi_ssid: str | Sequence[str] | None = None
    wifi_bssid: str | Sequence[str] | None = None

    rule_set: str | Sequence[str] | None = field(
        default=None, converter=maybe_map_to_tag
    )
    rule_set_ip_cidr_match_source: bool | None = None

    ip_accept_any: bool | None = None

    match_response: bool | None = None
    response_rcode: None = None
    response_answer: None = None
    response_ns: None = None
    response_extra: None = None

    invert: bool | None = None

    # Deprecated
    # ip_cidr: NetworkCIDR | Sequence[NetworkCIDR] | None = None
    # ip_is_private: bool | None = None


@define(slots=False)
class _BaseDnsRouteRule(BaseDnsRule):
    server: str | BaseDnsServer = field(converter=to_tag)
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
