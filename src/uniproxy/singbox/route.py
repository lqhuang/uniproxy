from __future__ import annotations

from typing import Literal, Sequence

from attrs import define, field

from uniproxy.abc import AbstractSingBox
from uniproxy.rules import (
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
    UniproxyRule,
)
from uniproxy.utils import flatmap_to_tag

from .base import BaseInbound, BaseOutbound
from .typing import RuleSetType, SniffProtocol


@define
class BaseRuleSet(AbstractSingBox):
    tag: str
    type: RuleSetType
    format: Literal["binary", "source"]

    def __str__(self) -> str:
        return str(self.tag)


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


@define
class Rule(AbstractSingBox):
    outbound: BaseOutbound | str

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
        converter=flatmap_to_tag,
    )
    rule_set_ip_cidr_match_source: bool | None = None
    invert: bool | None = None

    @classmethod
    def from_uniproxy(cls, rule: UniproxyRule) -> Rule:
        if not isinstance(rule, UniproxyRule):
            raise ValueError(f"Expected UniproxyRule, got {type(rule)}")

        match rule:
            case DomainRule(matcher=matcher, policy=policy) | DomainGroupRule(
                matcher=matcher, policy=policy
            ):
                return cls(
                    outbound=str(policy),
                    domain=matcher,
                )
            case DomainSuffixRule(
                matcher=matcher, policy=policy
            ) | DomainSuffixGroupRule(matcher=matcher, policy=policy):
                return cls(
                    outbound=str(policy),
                    domain_suffix=matcher,
                )
            case DomainKeywordRule(
                matcher=matcher, policy=policy
            ) | DomainKeywordGroupRule(matcher=matcher, policy=policy):
                return cls(
                    outbound=str(policy),
                    domain_keyword=matcher,
                )
            case (
                IPCidrRule(matcher=matcher, policy=policy)
                | IPCidrGroupRule(matcher=matcher, policy=policy)
                | IPCidr6Rule(matcher=matcher, policy=policy)
                | IPCidr6GroupRule(matcher=matcher, policy=policy)
            ):
                return cls(
                    outbound=str(policy),
                    ip_cidr=matcher,
                )
            case GeoIPRule(matcher=matcher, policy=policy):
                # TODO: add extra opts to give a prefix or suffix
                return cls(
                    outbound=str(policy),
                    rule_set=f"rs-geoip-{matcher}".lower(),
                )
            case RuleSetRule(matcher, policy) | DomainSetRule(
                matcher=matcher, policy=policy
            ):
                matcher = str(matcher)
                if matcher.startswith("http") and "://" in matcher:
                    raise ValueError(
                        f"Direct URL ({matcher}) is not supported currently while transforming from uniproxy external rule to sing-box rule"
                    )
                return cls(
                    outbound=str(policy),
                    rule_set=matcher,
                )
            case _:
                raise ValueError(f"Unsupported rule type yet: {type(rule)}")


@define
class Route(AbstractSingBox):
    rules: Sequence[Rule]
    """List of [[Route Rule]]"""
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
