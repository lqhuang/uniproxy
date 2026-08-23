from __future__ import annotations

from typing import Literal, assert_never, cast, overload
from uniproxy.typing import Backend

from uniproxy.clash.providers import RuleProvider as ClashRuleProvider
from uniproxy.clash.rules import Rule as ClashRule
from uniproxy.singbox.dns_rules import DnsRule as SingBoxDnsRule
from uniproxy.singbox.route import RuleSet as SingBoxRuleSet
from uniproxy.singbox.route_rules import Rule as SingBoxRouteRule
from uniproxy.surge.rules import Rule as SurgeRule

from .routing import ClashRouting, PolicyRouting, SingBoxRouting, SurgeRouting


def merge_surge_routing(*routings: SurgeRouting) -> SurgeRouting:
    """Merge multiple Surge routing configurations into one."""
    rules: list[SurgeRule] = []
    for routing in routings:
        rules.extend(routing.rules)
    return SurgeRouting(rules=tuple(rules))


def merge_clash_routing(*routings: ClashRouting) -> ClashRouting:
    """Merge multiple Clash routing configurations into one."""
    rules: list[ClashRule] = []
    rule_providers: dict[str, ClashRuleProvider] = {}
    for routing in routings:
        rules.extend(routing.rules)
        rule_providers.update({
            provider.name: provider for provider in routing.rule_providers
        })
    return ClashRouting(
        rules=tuple(rules), rule_providers=tuple(rule_providers.values())
    )


def merge_singbox_routing(*routings: SingBoxRouting) -> SingBoxRouting:
    """Merge multiple SingBox routing configurations into one."""
    route_rules: list[SingBoxRouteRule] = []
    dns_rules: list[SingBoxDnsRule] = []
    rule_sets: set[SingBoxRuleSet] = set()
    for routing in routings:
        route_rules.extend(routing.route_rules)
        dns_rules.extend(routing.dns_rules)
        rule_sets.update(routing.rule_sets)
    return SingBoxRouting(
        route_rules=tuple(route_rules),
        dns_rules=tuple(dns_rules),
        rule_sets=tuple(rule_sets),
    )


@overload
def merge_policy_routing(
    backend: Literal["surge"], *routings: SurgeRouting
) -> SurgeRouting: ...
@overload
def merge_policy_routing(
    backend: Literal["sing-box"], *routings: SingBoxRouting
) -> SingBoxRouting: ...
@overload
def merge_policy_routing(
    backend: Literal["clash"], *routings: ClashRouting
) -> ClashRouting: ...


def merge_policy_routing(backend: Backend, *routings: PolicyRouting) -> PolicyRouting:
    """Merge multiple Policy routing configurations into one."""
    if backend == "surge":
        # pyrefly: ignore [bad-argument-type]
        return merge_surge_routing(*routings)
    elif backend == "clash":
        # pyrefly: ignore [bad-argument-type]
        return merge_clash_routing(*routings)
    elif backend == "sing-box":
        # pyrefly: ignore [bad-argument-type]
        return merge_singbox_routing(*routings)
    else:
        assert_never(backend)
