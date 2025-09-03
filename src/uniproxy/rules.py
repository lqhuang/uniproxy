from __future__ import annotations

from typing import Literal, Union

from attrs import define

from uniproxy.base import BaseBasicRule, BaseGroupRule, BaseRule, ProtocolLike


@define
class DomainRule(BaseBasicRule):
    type: Literal["domain"] = "domain"


@define
class DomainGroupRule(BaseGroupRule):
    type: Literal["domain-group"] = "domain-group"


@define
class DomainSuffixRule(BaseBasicRule):
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainSuffixGroupRule(BaseGroupRule):
    type: Literal["domain-suffix-group"] = "domain-suffix-group"


@define
class DomainKeywordRule(BaseBasicRule):
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainKeywordGroupRule(BaseGroupRule):
    type: Literal["domain-keyword-group"] = "domain-keyword-group"


@define
class IPCidrRule(BaseBasicRule):
    no_resolve: bool | None = True
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class IPCidrGroupRule(BaseGroupRule):
    no_resolve: bool | None = True
    type: Literal["ip-cidr-group"] = "ip-cidr-group"


@define
class IPCidr6Rule(BaseBasicRule):
    no_resolve: bool | None = True
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class IPCidr6GroupRule(BaseGroupRule):
    no_resolve: bool | None = True
    type: Literal["ip-cidr6-group"] = "ip-cidr6-group"


@define
class GeoIPRule(BaseBasicRule):
    no_resolve: bool | None = True
    type: Literal["geoip"] = "geoip"


@define
class UserAgentRule(BaseBasicRule):
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(BaseBasicRule):
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(BaseBasicRule):
    type: Literal["process-name"] = "process-name"


@define
class AndRule(BaseBasicRule):
    type: Literal["and"] = "and"


@define
class OrRule(BaseBasicRule):
    type: Literal["or"] = "or"


@define
class NotRule(BaseBasicRule):
    type: Literal["not"] = "not"


@define
class SubnetRule(BaseBasicRule):
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(BaseBasicRule):
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(BaseBasicRule):
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(BaseBasicRule):
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(BaseBasicRule):
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(BaseBasicRule):
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(BaseBasicRule):
    type: Literal["script"] = "script"


@define
class CellularRadioRule(BaseBasicRule):
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(BaseBasicRule):
    type: Literal["device-name"] = "device-name"


@define
class DomainSetRule(BaseBasicRule):
    type: Literal["domain-set"] = "domain-set"


@define
class RuleSetRule(BaseBasicRule):
    type: Literal["rule-set"] = "rule-set"


@define
class FinalRule(BaseRule):
    policy: ProtocolLike
    type: Literal["final"] = "final"


UniproxyBasicRule = Union[
    DomainRule,
    DomainGroupRule,
    DomainSuffixRule,
    DomainSuffixGroupRule,
    DomainKeywordRule,
    DomainKeywordGroupRule,
    IPCidrRule,
    IPCidrGroupRule,
    IPCidr6Rule,
    IPCidr6GroupRule,
    GeoIPRule,
    UserAgentRule,
    UrlRegexRule,
    ProcessNameRule,
    AndRule,
    OrRule,
    NotRule,
    SubnetRule,
    DestPortRule,
    SrcPortRule,
    InPortRule,
    SrcIPRule,
    ProtocolRule,
    ScriptRule,
    CellularRadioRule,
    DeviceNameRule,
    DomainSetRule,
    RuleSetRule,
]
UniproxyGroupRule = Union[
    DomainGroupRule,
    DomainSuffixGroupRule,
    DomainKeywordGroupRule,
    IPCidrGroupRule,
    IPCidr6GroupRule,
]
UniproxyRule = Union[UniproxyBasicRule, UniproxyGroupRule, FinalRule]
