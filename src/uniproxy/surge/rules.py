from __future__ import annotations

from typing import Literal, Sequence

import gc

from attrs import define, field, fields

from uniproxy.providers import RuleProvider as UniproxyRuleProvider
from uniproxy.rules import (
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyRule,
)

from .base import BaseRule, BaseRuleProvider, ProtocolLike


@define
class SurgeRule(BaseRule):

    @classmethod
    def from_uniproxy(cls, rule: UniproxyRule) -> SurgeRule:
        gc.collect(1)
        for subcls in cls.__subclasses__():
            _fields = fields(subcls)
            if _fields.type.default == rule.type:
                if isinstance(rule.matcher, UniproxyRuleProvider):
                    matcher = rule.matcher.url
                else:
                    matcher = str(rule.matcher)

                if rule.type.find("ip-cidr") != -1:
                    inst = subcls(  # pyright: ignore[reportCallIssue]
                        policy=str(rule.policy),
                        matcher=matcher,
                        no_resolve=rule.no_resolve,  # type: ignore
                    )
                    print("yesh")
                else:
                    inst = subcls(  # pyright: ignore[reportCallIssue]
                        policy=str(rule.policy),
                        matcher=matcher,
                    )
                break
        else:
            raise NotImplementedError(
                f"Unknown rule type '{rule.type}' while transforming uniproxy rule to surge rule"
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
    ) -> Sequence[SurgeRule]:
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
class DomainRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(SurgeRule):
    matcher: str | BaseRuleProvider = field(
        converter=lambda x: x if isinstance(x, str) else x.url
    )
    policy: ProtocolLike | str
    force_remote_dns: bool | None = None
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr"] = "ip-cidr"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPCidr6Rule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr6"] = "ip-cidr6"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class GeoIPRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["geoip"] = "geoip"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPAsn(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-asn"] = "ip-asn"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class UserAgentRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["process-name"] = "process-name"


@define
class AndRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["and"] = "and"


@define
class OrRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["or"] = "or"


@define
class NotRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["not"] = "not"


@define
class SubnetRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["dest-port"] = "dest-port"


@define
class InPortRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["in-port"] = "in-port"


@define
class SrcPortRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["src-port"] = "src-port"


@define
class SrcIPRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["script"] = "script"


@define
class CellularRadioRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(SurgeRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["device-name"] = "device-name"


@define
class RuleSetRule(SurgeRule):
    matcher: Literal["SYSTEM", "LAN"] | str | BaseRuleProvider = field(
        converter=lambda x: x if isinstance(x, str) else x.url
    )
    policy: ProtocolLike | str
    type: Literal["rule-set"] = "rule-set"


@define(kw_only=True)
class FinalRule(SurgeRule):
    policy: ProtocolLike | str
    matcher: None = None
    dns_failed: bool | None = None
    type: Literal["final"] = "final"

    def __str__(self) -> str:
        if self.dns_failed:
            return f"{self.type.upper()},{self.policy},dns-failed"
        else:
            return f"{self.type.upper()},{self.policy}"
