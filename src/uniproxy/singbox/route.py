from __future__ import annotations

from typing import Literal, Sequence

from attrs import define

from .base import BaseInbound, BaseOutbound
from .typing import RuleSetType, SniffProtocol


@define
class BaseRuleSet:
    type: RuleSetType
    tag: str
    format: Literal["binary", "source"]


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
class Rule:
    outbound: BaseOutbound | str

    inbound: Sequence[BaseInbound] | Sequence[str] | None = None
    ip_version: Literal["4", "6", None] = None
    auth_user: str | None = None
    protocol: SniffProtocol | None = None
    network: str | None = None
    domain: str | None = None
    domain_suffix: str | None = None
    domain_keyword: str | None = None
    domain_regex: str | None = None
    ip_cidr: Sequence[str] | None = None
    ip_is_private: bool | None = None
    source_ip_cidr: Sequence[str] | None = None
    source_ip_is_private: bool | None = None
    source_port: int | None = None
    source_port_range: Sequence[str] | None = None
    port: Sequence[int] | None = None
    port_range: Sequence[str] | None = None
    rule_set: Sequence[str] | None = None
    rule_set_ipcidr_match_source: bool | None = None
    invert: bool | None = None


@define
class Route:
    rules: Sequence[Rule]
    rule_set: Sequence[BaseRuleSet]
    final: str | BaseOutbound | None = None
    auto_detect_interface: bool | None = None
    override_android_vpn: bool | None = None
    default_interface: str | None = None
    default_mark: int | None = None
