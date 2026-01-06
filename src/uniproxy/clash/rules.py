from __future__ import annotations

from typing import Literal, Mapping, Union
from uniproxy.typing import (
    BASIC_NO_RESOLABLE_RULES,
    BASIC_RULES,
    BasicNoResolableRuleType,
    BasicRuleType,
    GroupRuleType,
)

from attrs import define

from uniproxy.rules import BaseBasicRule as UniproxyBaseBasicRule
from uniproxy.rules import (
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyRule,
    is_basic_no_resolvable_rule,
    is_basic_rule,
)
from uniproxy.rules import FinalRule as UniproxyFinalRule
from uniproxy.shared import NoResoleMixin
from uniproxy.utils import to_name

from .base import BaseBasicRule
from .base import FinalRule as FinalRule


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
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(NoResoleMixin, BaseBasicRule):
    type: Literal["ip-cidr"] = "ip-cidr"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPCidr6Rule(NoResoleMixin, BaseBasicRule):
    type: Literal["ip-cidr6"] = "ip-cidr6"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class GeoIPRule(NoResoleMixin, BaseBasicRule):
    type: Literal["geoip"] = "geoip"

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
class SrcPortRule(BaseBasicRule):
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(BaseBasicRule):
    type: Literal["in-port"] = "in-port"


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
    type: Literal["rule-set"] = "rule-set"


ClashBasicRule = Union[
    DomainRule,
    DomainSuffixRule,
    DomainKeywordRule,
    IPCidrRule,
    IPCidr6Rule,
    GeoIPRule,
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

ClashRule = Union[ClashBasicRule, FinalRule]

_CLASH_RESOLVABLE_MAPPER: Mapping[
    BasicNoResolableRuleType, type[IPCidrRule | IPCidr6Rule | GeoIPRule]
] = {"ip-cidr": IPCidrRule, "ip-cidr6": IPCidr6Rule, "geoip": GeoIPRule}

_CLASH_MAPPER: Mapping[BasicRuleType, type[ClashBasicRule]] = {
    "domain": DomainRule,
    "domain-suffix": DomainSuffixRule,
    "domain-keyword": DomainKeywordRule,
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
    # "rule-set": RuleSetRule,
    # "domain-set": DomainSetRule,
}


def make_rules_from_uniproxy(rule: UniproxyRule) -> tuple[ClashRule, ...]:
    if rule.type == "ip-asn":
        raise NotImplementedError("`ip-asn` rule type not implemented yet for Clash")

    policy = to_name(rule.policy)

    match rule:
        case UniproxyBaseBasicRule(matcher=matcher, type=typ):
            if typ in BASIC_NO_RESOLABLE_RULES and is_basic_no_resolvable_rule(rule):
                return (
                    _CLASH_RESOLVABLE_MAPPER[typ](
                        matcher=to_name(matcher),
                        policy=policy,
                        no_resolve=rule.no_resolve,
                    ),
                )
            else:
                assert typ in BASIC_RULES
                return (_CLASH_MAPPER[typ](matcher=to_name(matcher), policy=policy),)
        case DomainGroupRule(matcher=matcher):
            return tuple(
                DomainRule(matcher=str(each), policy=policy) for each in matcher
            )
        case DomainSuffixGroupRule(matcher=matcher):
            return tuple(
                DomainSuffixRule(matcher=str(each), policy=policy) for each in matcher
            )
        case DomainKeywordGroupRule(matcher=matcher):
            return tuple(
                DomainKeywordRule(matcher=str(each), policy=policy) for each in matcher
            )
        case IPCidrGroupRule(matcher=matcher, no_resolve=no_resolve):
            return tuple(
                IPCidrRule(matcher=str(each), policy=policy, no_resolve=no_resolve)
                for each in matcher
            )
        case IPCidr6GroupRule(matcher=matcher, no_resolve=no_resolve):
            return tuple(
                IPCidr6Rule(matcher=str(each), policy=policy, no_resolve=no_resolve)
                for each in matcher
            )
        case UniproxyFinalRule(policy=policy):
            return (FinalRule(policy=str(policy)),)
        case _:
            raise ValueError("Invalid rule type")
