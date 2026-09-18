from __future__ import annotations

from typing import Mapping, Sequence

from uniproxy.surge.rules import (
    AndRule,
    CellularRadioRule,
    DestPortRule,
    DeviceNameRule,
    DomainKeywordRule,
    DomainRule,
    DomainSuffixRule,
    GeoIPRule,
    InPortRule,
    IPAsnRule,
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
from uniproxy.surge.rules import Rule as SurgeRule
from uniproxy.surge.rules import _BasicRule as SurgeBasicRule
from uniproxy.uniproxy.rules import DomainGroupRule as UniproxyDomainGroupRule
from uniproxy.uniproxy.rules import (
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyRule,
    is_basic_no_resolvable_rule,
    is_basic_rule,
)
from uniproxy.uniproxy.rules import SubnetRule as UniproxySubnetRule
from uniproxy.uniproxy.typing import BasicNoResolableRuleType, BasicRuleType
from uniproxy.utils import to_name, to_tag

_SURGE_MAPPER: Mapping[BasicRuleType, type[SurgeBasicRule]] = {
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
}

_SURGE_NO_RESOLVE_MAPPER: Mapping[
    BasicNoResolableRuleType, type[IPCidrRule | IPCidr6Rule | GeoIPRule | IPAsnRule]
] = {
    "ip-cidr": IPCidrRule,
    "ip-cidr6": IPCidr6Rule,
    "geoip": GeoIPRule,
    "ip-asn": IPAsnRule,
}


def surge_rules_from_uniproxy(rule: UniproxyRule) -> Sequence[SurgeRule]:
    policy = to_name(rule.policy)

    if is_basic_rule(rule):
        return (_SURGE_MAPPER[rule.type](matcher=to_name(rule.matcher), policy=policy),)  # type: ignore[reportArgumentType]
    elif is_basic_no_resolvable_rule(rule):
        return (
            _SURGE_NO_RESOLVE_MAPPER[rule.type](  # type: ignore[reportArgumentType]
                matcher=to_name(rule.matcher),  # type: ignore[reportArgumentType]
                policy=policy,
                no_resolve=rule.no_resolve,  # type: ignore[reportArgumentType]
            ),
        )
    elif isinstance(rule, UniproxyDomainGroupRule):
        return tuple(DomainRule(matcher=each, policy=policy) for each in rule.matcher)
    elif isinstance(rule, DomainSuffixGroupRule):
        return tuple(
            DomainSuffixRule(matcher=each, policy=policy) for each in rule.matcher
        )
    elif isinstance(rule, DomainKeywordGroupRule):
        return tuple(
            DomainKeywordRule(matcher=each, policy=policy) for each in rule.matcher
        )
    elif isinstance(rule, IPCidrGroupRule):
        return tuple(
            IPCidrRule(matcher=each, policy=policy, no_resolve=rule.no_resolve)
            for each in rule.matcher
        )
    elif isinstance(rule, IPCidr6GroupRule):
        return tuple(
            IPCidr6Rule(matcher=each, policy=policy, no_resolve=rule.no_resolve)
            for each in rule.matcher
        )
    else:
        raise ValueError(
            f"Unknown rule type '{rule.type}' while transforming uniproxy rule to surge rule"
        )
