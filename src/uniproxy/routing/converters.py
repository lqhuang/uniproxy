from __future__ import annotations

from typing import TYPE_CHECKING, Sequence, assert_never
from uniproxy.typing import Backend

from itertools import chain

from uniproxy.cross_converters.clash import clash_rules_from_uniproxy
from uniproxy.cross_converters.singbox import singbox_route_rule_from_uniproxy
from uniproxy.cross_converters.surge import surge_rules_from_uniproxy
from uniproxy.singbox.dns import BaseDnsServer
from uniproxy.singbox.dns_rules import DnsRouteRule
from uniproxy.singbox.route_rules import RouteRule as SingBoxRouteRule
from uniproxy.singbox.route_rules import Rule as SingBoxRule
from uniproxy.uniproxy.rules import UniproxyRule

from .routing import ClashRouting, SingBoxRouting, SurgeRouting

if TYPE_CHECKING:
    from .routing import PolicyRouting


def surge_routing_from_uniproxy(rules: Sequence[UniproxyRule]) -> SurgeRouting:
    return SurgeRouting(
        rules=tuple(
            chain.from_iterable(surge_rules_from_uniproxy(rule) for rule in rules)
        )
    )


def clash_routing_from_uniproxy(rules: Sequence[UniproxyRule]) -> ClashRouting:
    return ClashRouting(
        rules=tuple(
            chain.from_iterable(clash_rules_from_uniproxy(rule) for rule in rules)
        )
    )


def make_routing_from_uniproxy_rules(
    backend: Backend,
    rules: Sequence[UniproxyRule],
    *,
    dns_server: BaseDnsServer | str | None,
) -> PolicyRouting:
    if backend == "surge":
        return surge_routing_from_uniproxy(rules)
    elif backend == "clash":
        return clash_routing_from_uniproxy(rules)
    elif backend == "sing-box":
        assert dns_server is not None
        return singbox_routing_from_uniproxy(rules, dns_server=dns_server)
    else:
        assert_never(backend)


def singbox_routing_from_uniproxy(
    rules: Sequence[UniproxyRule],
    dns_server: BaseDnsServer | str,
    # merge_same_policy: bool = True,  # TODO
) -> SingBoxRouting:
    route_rules: list[SingBoxRule] = []
    dns_rules: list[DnsRouteRule] = []

    for rule in rules:
        route_rule = singbox_route_rule_from_uniproxy(rule)
        route_rules.append(route_rule)
        if isinstance(route_rule, SingBoxRouteRule) and (
            route_rule.domain
            or route_rule.domain_suffix
            or route_rule.domain_keyword
            or route_rule.domain_regex
        ):
            dns_rules.append(
                DnsRouteRule(
                    server=dns_server,
                    domain=route_rule.domain,
                    domain_suffix=route_rule.domain_suffix,
                    domain_keyword=route_rule.domain_keyword,
                    domain_regex=route_rule.domain_regex,
                )
            )

    return SingBoxRouting(route_rules=tuple(route_rules), dns_rules=tuple(dns_rules))
