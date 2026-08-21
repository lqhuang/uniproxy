from __future__ import annotations

from typing import Literal, Mapping, Sequence, override

from attrs import define, field

from uniproxy.singbox.route_rules import BaseRule, RejectRule, RouteRule, Rule
from uniproxy.singbox.typing import SniffProtocol
from uniproxy.uniproxy.base import BaseRule as UniproxyBaseRule
from uniproxy.uniproxy.rules import (
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainKeywordRule,
    DomainRule,
    DomainSuffixGroupRule,
    DomainSuffixRule,
    GeoIPRule,
    IPCidr6GroupRule,
    IPCidr6Rule,
    IPCidrGroupRule,
    IPCidrRule,
    ProcessNameRule,
    UniproxyRule,
    UserAgentRule,
)
from uniproxy.uniproxy.rules import FinalRule as UniproxyFinalRule
from uniproxy.utils import maybe_flatmap_to_str, to_tag


def unify_mixed_route_rules(rules: Sequence[Rule | UniproxyRule]) -> Sequence[Rule]:
    out_rules: list[Rule] = []
    for r in rules:
        if isinstance(r, BaseRule):
            out_rules.append(r)
        elif isinstance(r, UniproxyFinalRule):
            pass
        elif isinstance(r, UniproxyBaseRule):
            out_rules.append(route_rule_from_uniproxy(r))
        else:
            print(r)
            raise ValueError(f"Unexpected rule type: {type(r)}")
    return out_rules


def route_rule_from_uniproxy(rule: UniproxyRule) -> Rule:
    if not isinstance(rule, UniproxyBaseRule):
        raise ValueError(f"Expected type of Uniproxy Rules, got {type(rule)}")
    if isinstance(rule, UniproxyFinalRule):
        raise ValueError(f"Final rule is not expected here, got {type(rule)}")

    if str(rule.policy).upper() == "REJECT":
        return RejectRule(domain_suffix=maybe_flatmap_to_str(rule.matcher))
    elif str(rule.policy).upper() == "REJECT-DROP":
        return RejectRule(
            domain_suffix=maybe_flatmap_to_str(rule.matcher), method="drop"
        )
    else:
        ...  # continue to pattern matching

    match rule:
        case (
            DomainRule(matcher=matcher, policy=policy)
            | DomainGroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), domain=matcher)
        case (
            DomainSuffixRule(matcher=matcher, policy=policy)
            | DomainSuffixGroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), domain_suffix=matcher)
        case (
            DomainKeywordRule(matcher=matcher, policy=policy)
            | DomainKeywordGroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), domain_keyword=matcher)
        case (
            IPCidrRule(matcher=matcher, policy=policy)
            | IPCidrGroupRule(matcher=matcher, policy=policy)
            | IPCidr6Rule(matcher=matcher, policy=policy)
            | IPCidr6GroupRule(matcher=matcher, policy=policy)
        ):
            return RouteRule(outbound=str(policy), ip_cidr=matcher)
        case GeoIPRule(matcher=matcher, policy=policy):
            # TODO: add extra opts to give a prefix or suffix
            return RouteRule(
                outbound=str(policy), rule_set=f"rs-geoip-{matcher}".lower()
            )
        case ProcessNameRule(matcher=matcher, policy=policy):
            return RouteRule(outbound=str(policy), process_name=matcher)
        case UserAgentRule(matcher=matcher, policy=policy):
            return RouteRule(outbound=str(policy), rule_set=f"rs-useragent-{matcher}")
        # case (
        #     RuleSetRule(matcher, policy) | DomainSetRule(matcher=matcher, policy=policy)
        # ):
        #     matcher = str(matcher)
        #     if matcher.startswith("http") and "://" in matcher:
        #         raise ValueError(
        #             f"Direct URL ({matcher}) is not supported currently while transforming from uniproxy external rule to sing-box rule"
        #         )
        #     return RouteRule(outbound=str(policy), rule_set=matcher)
        case _:
            print(rule)
            raise ValueError(f"Unsupported rule type yet: {type(rule)}")
