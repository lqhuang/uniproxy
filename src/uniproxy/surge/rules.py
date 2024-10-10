from __future__ import annotations

from typing import Literal, Mapping
from uniproxy.typing import RuleType

from attrs import define, field

from uniproxy.rules import (
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyRule,
)
from uniproxy.utils import to_name

from .base import BaseRule as SurgeRule
from .base import BaseRuleProvider, ProtocolLike


@define
class DomainRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(SurgeRule):
    matcher: str | BaseRuleProvider = field(
        converter=lambda x: x if isinstance(x, str) else x.url
    )
    policy: ProtocolLike | str
    force_remote_dns: bool | None = None
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr"] = "ip-cidr"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPCidr6Rule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr6"] = "ip-cidr6"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class GeoIPRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["geoip"] = "geoip"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPAsn(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-asn"] = "ip-asn"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class UserAgentRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["process-name"] = "process-name"


@define
class AndRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["and"] = "and"


@define
class OrRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["or"] = "or"


@define
class NotRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["not"] = "not"


@define
class SubnetRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["dest-port"] = "dest-port"


@define
class InPortRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["in-port"] = "in-port"


@define
class SrcPortRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["src-port"] = "src-port"


@define
class SrcIPRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["script"] = "script"


@define
class CellularRadioRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["device-name"] = "device-name"


@define
class RuleSetRule(SurgeRule):
    matcher: Literal["SYSTEM", "LAN"] | str | BaseRuleProvider = field(
        converter=lambda x: x if isinstance(x, str) else x.url
    )
    policy: ProtocolLike | str
    type: Literal["rule-set"] = "rule-set"


@define
class FinalRule(SurgeRule):
    matcher: None
    policy: ProtocolLike | str
    dns_failed: bool | None = None
    type: Literal["final"] = "final"

    def __str__(self) -> str:
        if self.dns_failed:
            return f"{self.type.upper()},{self.policy},dns-failed"
        else:
            return f"{self.type.upper()},{self.policy}"


_SURGE_MAPPER: Mapping[RuleType, type[SurgeRule]] = {
    "domain": DomainRule,
    "domain-suffix": DomainSuffixRule,
    "domain-keyword": DomainKeywordRule,
    "ip-cidr": IPCidrRule,
    "ip-cidr6": IPCidr6Rule,
    "geoip": GeoIPRule,
    "ip-asn": IPAsn,
    "user-agent": UserAgentRule,
    "url-regex": UrlRegexRule,
    "process-name": ProcessNameRule,
    "and": AndRule,
    "or": OrRule,
    "not": NotRule,
    "subnet": SubnetRule,
    "dest-port": DestPortRule,
    "in-port": InPortRule,
    "src-port": SrcPortRule,
    "src-ip": SrcIPRule,
    "protocol": ProtocolRule,
    "script": ScriptRule,
    "cellular-radio": CellularRadioRule,
    "device-name": DeviceNameRule,
    "rule-set": RuleSetRule,
    "final": FinalRule,
    "domain-set": DomainSetRule,
}


def make_rules_from_uniproxy(
    rule: (
        UniproxyRule
        | DomainKeywordGroupRule
        | DomainSuffixGroupRule
        | DomainGroupRule
        | IPCidrGroupRule
        | IPCidr6GroupRule
    ),
) -> tuple[SurgeRule, ...]:
    policy = to_name(rule.policy)

    match rule:
        case UniproxyRule(matcher=matcher, type=typ):
            return (
                _SURGE_MAPPER[typ](
                    matcher=to_name(matcher) if matcher is not None else None,
                    policy=policy,
                    type=typ,
                ),
            )
        case DomainGroupRule(matcher=matcher):
            return tuple(DomainRule(matcher=each, policy=policy) for each in matcher)
        case DomainSuffixGroupRule(matcher=matcher):
            return tuple(
                DomainSuffixRule(matcher=each, policy=policy) for each in matcher
            )
        case DomainKeywordGroupRule(matcher=matcher):
            return tuple(
                DomainKeywordRule(matcher=each, policy=policy) for each in matcher
            )
        case IPCidrGroupRule(matcher=matcher, no_resolve=no_resolve):
            return tuple(
                IPCidrRule(matcher=each, policy=policy, no_resolve=no_resolve)
                for each in matcher
            )
        case IPCidr6GroupRule(matcher=matcher, no_resolve=no_resolve):
            return tuple(
                IPCidr6Rule(matcher=each, policy=policy, no_resolve=no_resolve)
                for each in matcher
            )
        case _:
            raise ValueError(
                f"Unknown rule type '{rule.type}' while transforming uniproxy rule to surge rule"
            )
