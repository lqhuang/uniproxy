from __future__ import annotations

from typing import Iterable

from uniproxy.base import RuleProviderLike


def filter_out_rule_provider(providers: Iterable[RuleProviderLike]) -> tuple[str, ...]:
    return tuple((p for p in providers if isinstance(p, str)))
