from __future__ import annotations

from typing import Mapping

from uniproxy.clash.rules import (
    AndRule,
    CellularRadioRule,
    DestPortRule,
    DeviceNameRule,
    DomainKeywordRule,
    DomainRule,
    DomainSuffixRule,
    FinalRule,
    GeoIPRule,
    InPortRule,
    IPCidr6Rule,
    IPCidrRule,
    NotRule,
    OrRule,
    ProcessNameRule,
    ProtocolRule,
    ScriptRule,
    SrcIPRule,
    SrcPortRule,
    SubnetRule,
    UrlRegexRule,
    UserAgentRule,
)
from uniproxy.clash.rules import Rule as ClashRule
from uniproxy.clash.rules import _BasicRule as ClashBasicRule
from uniproxy.uniproxy.rules import (
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyRule,
    is_basic_no_resolvable_rule,
    is_basic_rule,
)
from uniproxy.uniproxy.rules import FinalRule as UniproxyFinalRule
from uniproxy.uniproxy.typing import (
    BasicNoResolableRuleType,
    BasicRuleType,
    GroupRuleType,
)
from uniproxy.utils import to_name

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


def clash_rules_from_uniproxy(rule: UniproxyRule) -> tuple[ClashRule, ...]:
    if rule.type == "ip-asn":
        raise NotImplementedError("`ip-asn` rule type not implemented yet for Clash")

    policy = to_name(rule.policy)

    if is_basic_rule(rule):
        typ = rule.type
        matcher = rule.matcher
        if is_basic_no_resolvable_rule(rule):
            return (
                _CLASH_RESOLVABLE_MAPPER[typ](
                    matcher=to_name(matcher), policy=policy, no_resolve=rule.no_resolve
                ),
            )
        else:
            return (_CLASH_MAPPER[typ](matcher=to_name(matcher), policy=policy),)
    else:
        match rule:
            case DomainGroupRule(matcher=matcher):
                return tuple(
                    DomainRule(matcher=each, policy=policy) for each in matcher
                )
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
            case UniproxyFinalRule(policy=policy):
                return (FinalRule(policy=str(policy)),)
            case _:
                raise ValueError("Invalid rule type")
