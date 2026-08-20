from __future__ import annotations

from typing import Literal, Mapping, Sequence, override

from functools import cached_property

from attrs import define, field

from uniproxy.abc import BaseTaggable
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
from uniproxy.uniproxy.typing import BasicNoResolableRuleType, BasicRuleType
from uniproxy.utils import to_name, to_tag

from .base import AbstractSurge, BaseBasicRule, BaseRule, ProtocolLike, RuleLike

#
# Mixins
#


@define(slots=False)
class _NoResoleMixin(BaseTaggable):
    """
    Applies to:

    IP-CIDR, IP-CIDR6, GEOIP, IP-ASN, RULE-SET, DOMAIN-SET

    Effect:

    Skip the rule for unresolved domain requests instead of triggering a DNS lookup. On RULE-SET, applies to every sub-rule.
    """

    no_resolve: bool | None = None

    @override
    @cached_property
    def to_tag(self) -> str:
        if self.no_resolve:
            return f"{super().to_tag},no-resolve"
        else:
            return super().to_tag


@define(slots=False)
class _ExtendedMatchingMixin(BaseTaggable):
    """
    Applies to:

    DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-WILDCARD, URL-REGEX, RULE-SET, DOMAIN-SET

    Effect:

    Also match the TLS SNI and the HTTP Host header (or `:authority`). On `RULE-SET`/`DOMAIN-SET`, applies to every entry.
    """

    extended_matching: bool | None = None

    @override
    @cached_property
    def to_tag(self) -> str:
        if self.extended_matching:
            return f"{super().to_tag},extended-matching"
        else:
            return super().to_tag


@define(slots=False)
class _PreMatchingMixin(BaseTaggable):
    pre_matching: bool | None = None

    @override
    @cached_property
    def to_tag(self) -> str:
        if self.pre_matching:
            return f"{super().to_tag},pre-matching"
        else:
            return super().to_tag


#
# [Domain Rules](https://manual.nssurge.com/rules/domain.html)
#


@define
class DomainRule(_PreMatchingMixin, _ExtendedMatchingMixin, BaseBasicRule):
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(_PreMatchingMixin, _ExtendedMatchingMixin, BaseBasicRule):
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(_PreMatchingMixin, _ExtendedMatchingMixin, BaseBasicRule):
    """
    Matches the hostname against a wildcard pattern:

    - *` matches any number of characters, including none. It also crosses dots,
      so `*.example.com` matches `a.b.example.com`.
    - `?` matches exactly one character.
    - `[...]` character classes are supported.

    Matching is case-insensitive. Use `DOMAIN-WILDCARD` when `DOMAIN-SUFFIX` and
    `DOMAIN-KEYWORD` are not precise enough, e.g. to match a naming pattern
    like `cdn?.example.com`.

    Example:

    ```
    DOMAIN-WILDCARD,api-*.example.com,Proxy
    ```
    """

    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainWildCardRule(_PreMatchingMixin, _ExtendedMatchingMixin, BaseBasicRule):
    type: Literal["domain-wildcard"] = "domain-wildcard"


@define
class DomainSetRule(_PreMatchingMixin, _ExtendedMatchingMixin, BaseBasicRule):
    force_remote_dns: bool | None = None
    type: Literal["domain-set"] = "domain-set"


#
# [IP Rules](https://manual.nssurge.com/rules/ip.html)
#


@define
class IPCidrRule(_PreMatchingMixin, _NoResoleMixin, BaseBasicRule):
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class IPCidr6Rule(_PreMatchingMixin, _NoResoleMixin, BaseBasicRule):
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class GeoIPRule(_PreMatchingMixin, _NoResoleMixin, BaseBasicRule):
    type: Literal["geoip"] = "geoip"


@define
class IPAsnRule(_PreMatchingMixin, _NoResoleMixin, BaseBasicRule):
    type: Literal["ip-asn"] = "ip-asn"


#
# [HTTP Rules](https://manual.nssurge.com/rules/http.html)
#


@define
class UserAgentRule(_ExtendedMatchingMixin, BaseBasicRule):
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(_ExtendedMatchingMixin, BaseBasicRule):
    type: Literal["url-regex"] = "url-regex"


#
# [Process Rules](https://manual.nssurge.com/rules/process.html)
#


@define
class ProcessNameRule(BaseBasicRule):
    type: Literal["process-name"] = "process-name"


#
# [Source and Port Rules](https://manual.nssurge.com/rules/source-and-port.html)
#


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
class DeviceNameRule(BaseBasicRule):
    type: Literal["device-name"] = "device-name"


# TODO: MacAddress(BaseRule)

#
# Protocol and Network Rules (https://manual.nssurge.com/rules/protocol-and-network.html)
#

_protocol_matchers = {
    "HTTP",
    "HTTPS",
    "TCP",
    "UDP",
    "QUIC",
    "STUN",
    "MTProto",
    "DOH",
    "DOH3",
    "DOQ",
    "DOT",
    "DNS",
}
type ProtocolMatcherType = Literal[
    "HTTP",
    "HTTPS",
    "TCP",
    "UDP",
    "QUIC",
    "STUN",
    "MTProto",
    "DOH",
    "DOH3",
    "DOQ",
    "DOT",
    "DNS",
]


@define(slots=False)
class _ProtocolRuleMixin:
    matcher: ProtocolMatcherType | str
    policy: ProtocolLike

    def __attr_post_init__(self) -> None:
        if self.matcher not in _protocol_matchers:
            raise ValueError(
                f"Invalid protocol matcher '{self.matcher}', must be one of {_protocol_matchers}"
            )


@define
class ProtocolRule(_ProtocolRuleMixin, BaseBasicRule):
    """
    The comparison is case-sensitive; write the keywords exactly as listed above.

    Two keywords act as umbrella matchers:

    - `PROTOCOL,TCP` also matches HTTP, HTTPS, and MTProto connections, so a
      single rule can cover all TCP-based traffic.
    - `PROTOCOL,UDP` also matches QUIC and STUN connections.

    Use `MTProto` to match connections accepted by the built-in MTProto proxy server.

    ```text
    PROTOCOL,MTProto,Proxy
    ```
    """

    type: Literal["protocol"] = "protocol"


# TODO: HostnameRule(BaseRule)


@define
class CellularRadioRule(BaseBasicRule):
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class SubnetRule(BaseBasicRule):
    type: Literal["subnet"] = "subnet"


#
# [Logical Rules](https://manual.nssurge.com/rules/logical.html)
#


@define
class AndRule(BaseBasicRule):
    type: Literal["and"] = "and"


@define
class OrRule(BaseBasicRule):
    type: Literal["or"] = "or"


@define
class NotRule(BaseBasicRule):
    type: Literal["not"] = "not"


#
# [Script Rule](https://manual.nssurge.com/rules/script.html)
#


@define
class ScriptRule(BaseBasicRule):
    requires_resolve: bool | None = None
    type: Literal["script"] = "script"

    @override
    @cached_property
    def to_tag(self) -> str:
        if self.requires_resolve:
            return f"{super().to_tag},requires-resolve"
        else:
            return f"{super().to_tag}"


#
# [Rule Sets](https://manual.nssurge.com/rules/ruleset.html)
#


@define(slots=False)
class _RuleSetRuleMixin:
    matcher: Literal["SYSTEM", "LAN"] | str


@define
class RuleSetRule(
    _PreMatchingMixin, _ExtendedMatchingMixin, _RuleSetRuleMixin, BaseRule
):
    type: Literal["rule-set"] = "rule-set"


#
# Final Rule
#


@define
class FinalRule(BaseRule):
    policy: ProtocolLike
    dns_failed: bool | None = None
    type: Literal["final"] = "final"

    @override
    @cached_property
    def to_tag(self) -> str:
        if self.dns_failed:
            return f"final.{to_tag(self.policy)},dns-failed"
        else:
            return f"final.{to_tag(self.policy)}"


type _SurgeBasicRule = (
    DomainRule
    | DomainSuffixRule
    | DomainKeywordRule
    | DomainWildCardRule
    | IPCidrRule
    | IPCidr6Rule
    | GeoIPRule
    | IPAsnRule
    | UserAgentRule
    | UrlRegexRule
    | ProcessNameRule
    | AndRule
    | OrRule
    | NotRule
    | SubnetRule
    | DestPortRule
    | InPortRule
    | SrcPortRule
    | SrcIPRule
    | ProtocolRule
    | ScriptRule
    | CellularRadioRule
    | DeviceNameRule
)

type _SurgeExternalRule = RuleSetRule | DomainSetRule

type SurgeRule = _SurgeBasicRule | _SurgeExternalRule | FinalRule


_SURGE_MAPPER: Mapping[BasicRuleType, type[_SurgeBasicRule]] = {
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


def make_rules_from_uniproxy(rule: UniproxyRule) -> Sequence[SurgeRule]:
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
