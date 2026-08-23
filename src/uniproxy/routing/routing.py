from __future__ import annotations

from typing import Iterable, Sequence

from xattrs import define, field

from uniproxy.clash.providers import RuleProvider as ClashRuleProvider
from uniproxy.clash.rules import Rule as ClashRule
from uniproxy.singbox.dns_rules import DnsRule
from uniproxy.singbox.route import Rule as RouteRule
from uniproxy.singbox.route import RuleSet
from uniproxy.surge.rules import Rule as SurgeRule


@define
class SingBoxRouting:
    """
    SingBox routing types and utils.

    1. DNS rules
    2. Routing rules
    3. Rule sets
    """

    route_rules: Sequence[RouteRule] = field(factory=tuple)
    dns_rules: Sequence[DnsRule] = field(factory=tuple)
    rule_sets: Sequence[RuleSet] = field(factory=tuple)


@define
class SurgeRouting:
    rules: Sequence[SurgeRule] = field(factory=tuple)


@define
class ClashRouting:
    rules: Sequence[ClashRule] = field(factory=tuple)
    rule_providers: Sequence[ClashRuleProvider] = field(factory=tuple)


type PolicyRouting = SingBoxRouting | SurgeRouting | ClashRouting
