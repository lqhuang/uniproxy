from __future__ import annotations

from typing import Literal, Sequence

from attrs import define

from uniproxy.base import BaseGroupRule as UniproxyGroupRule
from uniproxy.base import BaseRule as UniproxyRule
from uniproxy.base import BaseRuleProvider, ProtocolLike


@define
class DomainRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["domain"] = "domain"


@define
class DomainGroupRule(UniproxyGroupRule):
    matcher: Sequence[str]
    policy: ProtocolLike
    type: Literal["domain-group"] = "domain-group"


@define
class DomainSuffixRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainSuffixGroupRule(UniproxyGroupRule):
    matcher: Sequence[str]
    policy: ProtocolLike
    type: Literal["domain-suffix-group"] = "domain-suffix-group"


@define
class DomainKeywordRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainKeywordGroupRule(UniproxyGroupRule):
    matcher: Sequence[str]
    policy: ProtocolLike
    type: Literal["domain-keyword-group"] = "domain-keyword-group"


@define
class IPCidrRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    no_resolve: bool | None = None
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class IPCidrGroupRule(UniproxyGroupRule):
    matcher: Sequence[str]
    policy: ProtocolLike
    no_resolve: bool | None = None
    type: Literal["ip-cidr-group"] = "ip-cidr-group"


@define
class IPCidr6Rule(UniproxyRule):
    matcher: str
    policy: ProtocolLike
    no_resolve: bool | None = None
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class IPCidr6GroupRule(UniproxyGroupRule):
    matcher: Sequence[str]
    policy: ProtocolLike
    no_resolve: bool | None = None
    type: Literal["ip-cidr6-group"] = "ip-cidr6-group"


@define
class GeoIPRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["geoip"] = "geoip"


@define
class UserAgentRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["process-name"] = "process-name"


@define
class AndRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["and"] = "and"


@define
class OrRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["or"] = "or"


@define
class NotRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["not"] = "not"


@define
class SubnetRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["script"] = "script"


@define
class CellularRadioRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["device-name"] = "device-name"


@define
class FinalRule(UniproxyRule):
    matcher: None
    policy: ProtocolLike
    type: Literal["final"] = "final"

    def __attrs_post_init__(self):
        if self.policy is None:
            raise ValueError("FinalRule must have a policy, cannot be None")


@define
class DomainSetRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["domain-set"] = "domain-set"


@define
class RuleSetRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike
    type: Literal["rule-set"] = "rule-set"
