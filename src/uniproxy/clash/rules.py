from __future__ import annotations

from typing import Literal, Sequence

import gc

from attrs import define, fields

from uniproxy.providers import RuleProvider as UniproxyRuleProvider
from uniproxy.rules import (
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyRule,
)

from .base import BaseRule, ProtocolLike
from .providers import RuleProvider


@define
class ClashRule(BaseRule):

    @classmethod
    def from_uniproxy(cls, rule: UniproxyRule) -> ClashRule:
        gc.collect(1)
        for subcls in cls.__subclasses__():
            _fields = fields(subcls)
            if _fields.type.default == rule.type:
                if isinstance(rule.matcher, UniproxyRuleProvider):
                    matcher = rule.matcher.url
                else:
                    matcher = str(rule.matcher)
                inst = subcls(  # pyright: ignore[reportCallIssue]
                    policy=str(rule.policy),
                    matcher=matcher,
                )
                break
        else:
            raise NotImplementedError(
                f"Unknown rule type '{rule.type}' while transforming uniproxy rule to clash rule"
            )
        return inst

    @classmethod
    def from_group_rules(
        cls,
        rule: (
            DomainKeywordGroupRule
            | DomainSuffixGroupRule
            | DomainGroupRule
            | IPCidrGroupRule
            | IPCidr6GroupRule
        ),
    ) -> Sequence[ClashRule]:
        match rule:
            case DomainGroupRule(matcher=matcher, policy=policy):
                return [DomainRule(matcher=each, policy=policy) for each in matcher]
            case DomainSuffixGroupRule(matcher=matcher, policy=policy):
                return [
                    DomainSuffixRule(matcher=each, policy=policy) for each in matcher
                ]
            case DomainKeywordGroupRule(matcher=matcher, policy=policy):
                return [
                    DomainKeywordRule(matcher=each, policy=policy) for each in matcher
                ]
            case IPCidrGroupRule(matcher=matcher, policy=policy, no_resolve=no_resolve):
                return [
                    IPCidrRule(matcher=each, policy=policy, no_resolve=no_resolve)
                    for each in matcher
                ]
            case IPCidr6GroupRule(
                matcher=matcher, policy=policy, no_resolve=no_resolve
            ):
                return [
                    IPCidr6Rule(matcher=each, policy=policy, no_resolve=no_resolve)
                    for each in matcher
                ]
            case _:
                raise TypeError("Invalid rule type")


@define
class DomainRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    no_resolve: bool | None = None
    type: Literal["ip-cidr"] = "ip-cidr"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPCidr6Rule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    no_resolve: bool | None = None
    type: Literal["ip-cidr6"] = "ip-cidr6"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class GeoIPRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    no_resolve: bool | None = None
    type: Literal["geoip"] = "geoip"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class UserAgentRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["process-name"] = "process-name"


@define
class AndRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["and"] = "and"


@define
class OrRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["or"] = "or"


@define
class NotRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["not"] = "not"


@define
class SubnetRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["script"] = "script"


@define
class CellularRadioRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(ClashRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["device-name"] = "device-name"


@define
class RuleSetRule(ClashRule):
    matcher: str | RuleProvider
    policy: str | ProtocolLike
    type: Literal["rule-set"] = "rule-set"
