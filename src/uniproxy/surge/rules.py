from __future__ import annotations

from typing import Literal, Mapping, Sequence, Union
from uniproxy.typing import BasicRuleType

from attrs import define, field

from uniproxy.rules import BaseBasicRule as UniproxyBaseBasicRule
from uniproxy.rules import DomainGroupRule as UniproxyDomainGroupRule
from uniproxy.rules import (
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyRule,
)
from uniproxy.utils import to_name

from .base import BaseBasicRule, BaseRule, BaseRuleProvider, ProtocolLike


@define
class DomainRule(BaseBasicRule):
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(BaseBasicRule):
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(BaseBasicRule):
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(BaseBasicRule):
    matcher: str | BaseRuleProvider = field(
        converter=lambda x: x if isinstance(x, str) else x.url
    )
    policy: ProtocolLike
    force_remote_dns: bool | None = None
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(BaseBasicRule):
    no_resolve: bool | None = True
    type: Literal["ip-cidr"] = "ip-cidr"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPCidr6Rule(BaseBasicRule):
    no_resolve: bool | None = True
    type: Literal["ip-cidr6"] = "ip-cidr6"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class GeoIPRule(BaseBasicRule):
    no_resolve: bool | None = True
    type: Literal["geoip"] = "geoip"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPAsn(BaseBasicRule):
    no_resolve: bool | None = True
    type: Literal["ip-asn"] = "ip-asn"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class UserAgentRule(BaseBasicRule):
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(BaseBasicRule):
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(BaseBasicRule):
    type: Literal["process-name"] = "process-name"


@define
class AndRule(BaseBasicRule):
    type: Literal["and"] = "and"


@define
class OrRule(BaseBasicRule):
    type: Literal["or"] = "or"


@define
class NotRule(BaseBasicRule):
    type: Literal["not"] = "not"


@define
class SubnetRule(BaseBasicRule):
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(BaseBasicRule):
    type: Literal["dest-port"] = "dest-port"


@define
class InPortRule(BaseBasicRule):
    type: Literal["in-port"] = "in-port"


@define
class SrcPortRule(BaseBasicRule):
    type: Literal["src-port"] = "src-port"


@define
class SrcIPRule(BaseBasicRule):
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(BaseBasicRule):
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(BaseBasicRule):
    type: Literal["script"] = "script"


@define
class CellularRadioRule(BaseBasicRule):
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(BaseBasicRule):
    type: Literal["device-name"] = "device-name"


@define
class RuleSetRule(BaseBasicRule):
    matcher: Literal["SYSTEM", "LAN"] | str | BaseRuleProvider = field(
        converter=lambda x: x if isinstance(x, str) else x.url
    )
    policy: ProtocolLike | str
    type: Literal["rule-set"] = "rule-set"


@define
class FinalRule(BaseRule):
    policy: ProtocolLike
    dns_failed: bool | None = None
    type: Literal["final"] = "final"

    def __str__(self) -> str:
        if self.dns_failed:
            return f"{self.type.upper()},{self.policy},dns-failed"
        else:
            return f"{self.type.upper()},{self.policy}"


_SurgeBasicRule = Union[
    DomainRule,
    DomainSuffixRule,
    DomainKeywordRule,
    IPCidrRule,
    IPCidr6Rule,
    GeoIPRule,
    IPAsn,
    UserAgentRule,
    UrlRegexRule,
    ProcessNameRule,
    AndRule,
    OrRule,
    NotRule,
    SubnetRule,
    DestPortRule,
    InPortRule,
    SrcPortRule,
    SrcIPRule,
    ProtocolRule,
    ScriptRule,
    CellularRadioRule,
    DeviceNameRule,
    RuleSetRule,
    DomainSetRule,
]

SurgeRule = Union[_SurgeBasicRule, FinalRule]

_SURGE_MAPPER: Mapping[BasicRuleType, type[_SurgeBasicRule]] = {
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
    "domain-set": DomainSetRule,
}


def make_rules_from_uniproxy(rule: UniproxyRule) -> Sequence[SurgeRule]:
    policy = to_name(rule.policy)

    if isinstance(rule, UniproxyBaseBasicRule):
        return (_SURGE_MAPPER[rule.type](matcher=to_name(rule.matcher), policy=policy),)
    elif isinstance(rule, UniproxyDomainGroupRule):
        return tuple(
            DomainRule(matcher=str(each), policy=policy) for each in rule.matcher
        )
    elif isinstance(rule, DomainSuffixGroupRule):
        return tuple(
            DomainSuffixRule(matcher=str(each), policy=policy) for each in rule.matcher
        )
    elif isinstance(rule, DomainKeywordGroupRule):
        return tuple(
            DomainKeywordRule(matcher=str(each), policy=policy) for each in rule.matcher
        )
    elif isinstance(rule, IPCidrGroupRule):
        return tuple(
            IPCidrRule(matcher=str(each), policy=policy, no_resolve=rule.no_resolve)
            for each in rule.matcher
        )
    elif isinstance(rule, IPCidr6GroupRule):
        return tuple(
            IPCidr6Rule(matcher=str(each), policy=policy, no_resolve=rule.no_resolve)
            for each in rule.matcher
        )
    else:
        raise ValueError(
            f"Unknown rule type '{rule.type}' while transforming uniproxy rule to surge rule"
        )
