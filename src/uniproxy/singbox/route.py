from typing import Literal

from enum import StrEnum

from .base import BaseInbound, BaseOutbound
from .shared import SniffProtocol


class RuleSetType(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"


class BaseRuleSet:
    tag: str
    type: RuleSetType
    format: Literal["binary"] = "binary"


class LocalRuleSet(BaseRuleSet):
    type: Literal[RuleSetType.LOCAL] = RuleSetType.LOCAL
    path: str


class RemoteRuleSet(BaseRuleSet):
    type: Literal[RuleSetType.REMOTE] = RuleSetType.REMOTE
    url: str
    download_detour: str | BaseOutbound | None
    update_interval: str


class Rule:
    outbound: BaseOutbound | str
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
    port: list[int] | None
    port_range: list[str] | None = None
    rule_set: list[str] | None = None
    rule_set_ipcidr_match_source: bool | None = None
    invert: bool | None = None


class Route:
    rules: list[Rule]
    rule_set: list[BaseRuleSet]
    final: str | None = None
    auto_detect_interface: bool = False
    override_android_vpn: bool = False
    default_interface: str | None = None
    default_mark: int | None = None
