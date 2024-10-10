from __future__ import annotations

from typing import Literal, Mapping
from uniproxy.typing import BasicRuleType

from attrs import define

from uniproxy.rules import (
    DomainGroupRule,
    DomainKeywordGroupRule,
    DomainSuffixGroupRule,
    IPCidr6GroupRule,
    IPCidrGroupRule,
    UniproxyBasicRule,
    UniproxyGroupRule,
)
from uniproxy.utils import to_name

from .base import BaseBasicRule as ClashRule
from .base import FinalRule as FinalRule
from .base import ProtocolLike
from .providers import RuleProvider


@define
class DomainRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(ClashRule):
    matcher: str
    policy: ProtocolLike
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
    policy: ProtocolLike
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
    policy: ProtocolLike
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
    policy: ProtocolLike
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["process-name"] = "process-name"


@define
class AndRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["and"] = "and"


@define
class OrRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["or"] = "or"


@define
class NotRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["not"] = "not"


@define
class SubnetRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["script"] = "script"


@define
class CellularRadioRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(ClashRule):
    matcher: str
    policy: ProtocolLike
    type: Literal["device-name"] = "device-name"


@define
class RuleSetRule(ClashRule):
    matcher: str | RuleProvider
    policy: ProtocolLike
    type: Literal["rule-set"] = "rule-set"


_CLASH_MAPPER: Mapping[BasicRuleType, type[ClashRule]] = {
    "domain": DomainRule,
    "domain-suffix": DomainSuffixRule,
    "domain-keyword": DomainKeywordRule,
    "ip-cidr": IPCidrRule,
    "ip-cidr6": IPCidr6Rule,
    "geoip": GeoIPRule,
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
    "rule-set": RuleSetRule,
    "domain-set": DomainSetRule,
}


def make_rules_from_uniproxy(
    rule: UniproxyBasicRule | UniproxyGroupRule,
) -> tuple[ClashRule, ...]:
    policy = to_name(rule.policy)

    match rule:
        case UniproxyBasicRule(matcher=matcher, type=typ):
            if typ == "ip-asn":
                raise NotImplementedError(
                    "`ip-asn` rule type not implemented yet for Clash"
                )
            return (
                _CLASH_MAPPER[typ](
                    matcher=to_name(matcher),
                    policy=policy,
                    type=typ,
                ),
            )
        case DomainGroupRule(matcher=matcher):
            return tuple(
                DomainRule(matcher=str(each), policy=policy) for each in matcher
            )
        case DomainSuffixGroupRule(matcher=matcher):
            return tuple(
                DomainSuffixRule(matcher=str(each), policy=policy) for each in matcher
            )
        case DomainKeywordGroupRule(matcher=matcher):
            return tuple(
                DomainKeywordRule(matcher=str(each), policy=policy) for each in matcher
            )
        case IPCidrGroupRule(matcher=matcher, no_resolve=no_resolve):
            return tuple(
                IPCidrRule(matcher=str(each), policy=policy, no_resolve=no_resolve)
                for each in matcher
            )
        case IPCidr6GroupRule(matcher=matcher, no_resolve=no_resolve):
            return tuple(
                IPCidr6Rule(matcher=str(each), policy=policy, no_resolve=no_resolve)
                for each in matcher
            )
        case _:
            raise ValueError("Invalid rule type")
