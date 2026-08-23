from __future__ import annotations

from typing import Literal, Sequence, assert_never

from uniproxy.cross_converters.clash import clash_rules_from_uniproxy
from uniproxy.cross_converters.singbox import singbox_route_rule_from_uniproxy
from uniproxy.cross_converters.surge import surge_rules_from_uniproxy
from uniproxy.singbox.dns import BaseDnsServer
from uniproxy.singbox.dns_rules import DnsRouteRule
from uniproxy.singbox.route_rules import RouteRule as SingBoxRouteRule
from uniproxy.uniproxy.rules import UniproxyRule
from uniproxy.utils import to_name, to_tag

from .routing import ClashRouting, SingBoxRouting, SurgeRouting


def surge_routing_from_uniproxy(
    rules: Sequence[UniproxyRule],
) -> Sequence[SurgeRouting]:
    routing: list[SurgeRouting] = [
        SurgeRouting(rules=surge_rules_from_uniproxy(rule)) for rule in rules
    ]
    return routing


def clash_routing_from_uniproxy(
    rules: Sequence[UniproxyRule],
) -> Sequence[ClashRouting]:
    routing: list[ClashRouting] = [
        ClashRouting(rules=clash_rules_from_uniproxy(rule)) for rule in rules
    ]
    return routing


def fakeip_routing_from_uniproxy(
    backend: Literal["surge", "clash"], rules: Sequence[UniproxyRule]
) -> Sequence[ClashRouting] | Sequence[SurgeRouting]:
    if backend == "surge":
        return surge_routing_from_uniproxy(rules)
    elif backend == "clash":
        return clash_routing_from_uniproxy(rules)
    else:
        assert_never(backend)


def singbox_routing_from_uniproxy(
    rules: Sequence[UniproxyRule],
    dns_server: BaseDnsServer | str,
    merge_same_policy: bool = True,  # TODO
) -> Sequence[SingBoxRouting]:
    routing: list[SingBoxRouting] = []
    for rule in rules:
        route_rule = singbox_route_rule_from_uniproxy(rule)
        if isinstance(route_rule, SingBoxRouteRule) and (
            route_rule.domain
            or route_rule.domain_suffix
            or route_rule.domain_keyword
            or route_rule.domain_regex
        ):
            dns_rules = (
                DnsRouteRule(
                    server=dns_server,
                    domain=route_rule.domain,
                    domain_suffix=route_rule.domain_suffix,
                    domain_keyword=route_rule.domain_keyword,
                    domain_regex=route_rule.domain_regex,
                ),
            )
        else:
            dns_rules = ()

        routing.append(SingBoxRouting(route_rules=(route_rule,), dns_rules=dns_rules))

    return routing
