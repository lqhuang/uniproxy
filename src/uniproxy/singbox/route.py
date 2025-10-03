from __future__ import annotations

from typing import Literal, Sequence, Union

from attrs import define, field

from uniproxy.abc import AbstractSingBox
from uniproxy.rules import (
    BaseBasicRule,
    BaseGroupRule,
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainKeywordRule,
    DomainRule,
    DomainSetRule,
    DomainSuffixGroupRule,
    DomainSuffixRule,
    GeoIPRule,
    IPCidr6GroupRule,
    IPCidr6Rule,
    IPCidrGroupRule,
    IPCidrRule,
    RuleSetRule,
    UniproxyBasicRule,
    UniproxyGroupRule,
)
from uniproxy.utils import maybe_flatmap_to_tag

from .base import BaseDnsServer, BaseInbound, BaseOutbound, BaseRuleSet
from .typing import SniffProtocol


@define
class LocalRuleSet(BaseRuleSet):
    path: str

    type: Literal["local"] = "local"


@define
class RemoteRuleSet(BaseRuleSet):
    url: str
    download_detour: str | BaseOutbound | None = None
    update_interval: float | None = None

    type: Literal["remote"] = "remote"


#
# Route Rule
#

type FinalActionType = Literal["route", "reject", "hijack-dns"]
type NonFinalActionType = Literal["route-options", "sniff", "resolve"]
type RuleActionType = FinalActionType | NonFinalActionType


class BaseRule(AbstractSingBox): ...


class BaseFinalActionRule(BaseRule): ...


class BaseNonFinalActionRule(BaseRule): ...


@define(slots=False)
class RouteOptionFieldsMixin:
    inbound: Sequence[BaseInbound] | Sequence[str] | None = None
    ip_version: Literal["4", "6", None] = None
    auth_user: str | Sequence[str] | None = None
    protocol: SniffProtocol | None = None
    network: Literal["tcp", "udp"] | None = None
    domain: str | Sequence[str] | None = None
    domain_suffix: str | Sequence[str] | None = None
    domain_keyword: str | Sequence[str] | None = None
    domain_regex: str | Sequence[str] | None = None
    ip_cidr: str | Sequence[str] | None = None
    ip_is_private: bool | None = None
    source_ip_cidr: Sequence[str] | None = None
    source_ip_is_private: bool | None = None
    source_port: int | Sequence[int] | None = None
    source_port_range: str | Sequence[str] | None = None
    port: int | Sequence[int] | None = None
    port_range: str | Sequence[str] | None = None
    rule_set: str | Sequence[str] | BaseRuleSet | Sequence[BaseRuleSet] | None = field(
        default=None,
        # FIXME: This is a hack to make the converter work
        converter=maybe_flatmap_to_tag,
    )
    rule_set_ip_cidr_match_source: bool | None = None
    invert: bool | None = None


@define(slots=False)
class _RouteRule:
    outbound: BaseOutbound | str | None


@define
class RouteRule(RouteOptionFieldsMixin, _RouteRule, BaseFinalActionRule):
    action: Literal["route"] = "route"


@define(slots=False)
class _RejectRule:
    method: Literal["default", "drop"] | None = None
    """
    - `default`: Reply with TCP RST for TCP connections, and ICMP port unreachable for UDP packets.
    - `drop`: Drop packets.

    `default` by default
    """

    no_drop: bool | None = None
    """
    If not enabled, `method` will be temporarily overwritten to `drop` after 50 triggers in 30s.

    Not available when `method` is set to drop.
    """


@define
class RejectRule(RouteOptionFieldsMixin, _RejectRule, BaseFinalActionRule):
    """
    https://sing-box.sagernet.org/configuration/route/rule_action/#reject

    ```json
    {
        "action": "reject",
        "method": "default", // default
        "no_drop": false
    }
    ```

    Action `reject` rejects connections

    The specified method is used for reject tun connections if `sniff` action has not been performed yet.

    For non-tun connections and already established connections, will just be closed.
    """

    action: Literal["reject"] = "reject"


@define
class HijackDnsRule(BaseFinalActionRule):
    """
    https://sing-box.sagernet.org/configuration/route/rule_action/#hijack-dns

    ```json
    {
      "action": "hijack-dns"
    }
    ```
    """

    protocol: Literal["dns"] = "dns"
    action: Literal["hijack-dns"] = "hijack-dns"


@define
class SniffRule(BaseNonFinalActionRule):
    """
    Example
    =======

    ```json
    {
        "action": "sniff",
        "sniffer": [],
        "timeout": ""
    }
    ```

    `sniff` performs protocol sniffing on connections.

    For deprecated `inbound.sniff` options, it is considered to `sniff()` performed before routing.

    Ref
    ===

    - https://sing-box.sagernet.org/configuration/route/rule_action/#sniff
    """

    sniffer: Sequence[SniffProtocol] | None = None
    """
    Enabled sniffers.

    All sniffers enabled by default.

    Available protocol values an be found on in [[Protocol Sniff]]
    """

    timeout: str | None = None
    """
    Timeout for sniffing.

    `300ms` is used by default.
    """

    action: Literal["sniff"] = "sniff"


Rule = Union[RouteRule, RejectRule, HijackDnsRule, SniffRule]


@define
class Route(AbstractSingBox):
    rules: Sequence[Rule]
    """List of [[Rule]]"""

    rule_set: Sequence[BaseRuleSet] | None = None
    """List of [[rule-set]]"""

    final: str | BaseOutbound | None = field(
        default=None, converter=lambda x: str(x) if x is not None else None
    )
    """Default outbound tag. the first outbound will be used if empty."""

    auto_detect_interface: bool | None = None
    """
    > [!WARN] Only supported on Linux, Windows and macOS.

    Bind outbound connections to the default NIC by default to prevent routing loops under tun.

    Takes no effect if `outbound.bind_interface` is set.
    """

    override_android_vpn: bool | None = None
    """
    > [!WARN] Only supported on Android.

    Accept Android VPN as upstream NIC when `auto_detect_interface` enabled.
    """

    default_interface: str | None = None
    """
    > [!WARN] Only supported on Linux, Windows and macOS.

    Bind outbound connections to the specified NIC by default to prevent routing loops under tun.

    Takes no effect if `auto_detect_interface` is set.
    """

    default_mark: int | None = None
    """
    > [!WARN] Only supported on Linux.

    Set routing mark by default.

    Takes no effect if `outbound.routing_mark` is set.
    """

    default_domain_resolver: str | BaseDnsServer | None = field(
        default=None, converter=lambda x: str(x) if x is not None else None
    )
    """
    > [!NEW] Since sing-box 1.12.0

    Tag of target DNS server.
    """


def route_rule_from_uniproxy(rule: UniproxyBasicRule | UniproxyGroupRule) -> RouteRule:
    if not isinstance(rule, Union[UniproxyBasicRule, UniproxyGroupRule]):
        raise ValueError(f"Expected type of Uniproxy Rules, got {type(rule)}")

    match rule:
        case (
            DomainRule(matcher=matcher, policy=policy)
            | DomainGroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), domain=matcher)  # type: ignore[reportArgumentType, arg-type]
        case (
            DomainSuffixRule(matcher=matcher, policy=policy)
            | DomainSuffixGroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), domain_suffix=matcher)  # type: ignore[reportArgumentType, arg-type]
        case (
            DomainKeywordRule(matcher=matcher, policy=policy)
            | DomainKeywordGroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), domain_keyword=matcher)  # type: ignore[reportArgumentType, arg-type]
        case (
            IPCidrRule(matcher=matcher, policy=policy)
            | IPCidrGroupRule(matcher=matcher, policy=policy)
            | IPCidr6Rule(matcher=matcher, policy=policy)
            | IPCidr6GroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), ip_cidr=matcher)  # type: ignore[reportArgumentType, arg-type]
        case GeoIPRule(matcher=matcher, policy=policy):
            # TODO: add extra opts to give a prefix or suffix
            return RouteRule(
                outbound=str(policy), rule_set=f"rs-geoip-{matcher}".lower()
            )
        case (
            RuleSetRule(matcher, policy) | DomainSetRule(matcher=matcher, policy=policy)
        ):
            matcher = str(matcher)
            if matcher.startswith("http") and "://" in matcher:
                raise ValueError(
                    f"Direct URL ({matcher}) is not supported currently while transforming from uniproxy external rule to sing-box rule"
                )
            return RouteRule(outbound=str(policy), rule_set=matcher)
        case _:
            raise ValueError(f"Unsupported rule type yet: {type(rule)}")
