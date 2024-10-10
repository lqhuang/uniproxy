from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.base import BaseBasicRule as UniproxyBasicRule
from uniproxy.base import BaseGroupRule as UniproxyGroupRule
from uniproxy.base import FinalRule as FinalRule


@define
class DomainRule(UniproxyBasicRule):
    type: Literal["domain"] = "domain"


@define
class DomainGroupRule(UniproxyGroupRule):
    type: Literal["domain-group"] = "domain-group"


@define
class DomainSuffixRule(UniproxyBasicRule):
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainSuffixGroupRule(UniproxyGroupRule):
    type: Literal["domain-suffix-group"] = "domain-suffix-group"


@define
class DomainKeywordRule(UniproxyBasicRule):
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainKeywordGroupRule(UniproxyGroupRule):
    type: Literal["domain-keyword-group"] = "domain-keyword-group"


@define
class IPCidrRule(UniproxyBasicRule):

    no_resolve: bool | None = None
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class IPCidrGroupRule(UniproxyGroupRule):
    no_resolve: bool | None = None
    type: Literal["ip-cidr-group"] = "ip-cidr-group"


@define
class IPCidr6Rule(UniproxyBasicRule):
    matcher: str

    no_resolve: bool | None = None
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class IPCidr6GroupRule(UniproxyGroupRule):
    no_resolve: bool | None = None
    type: Literal["ip-cidr6-group"] = "ip-cidr6-group"


@define
class GeoIPRule(UniproxyBasicRule):
    type: Literal["geoip"] = "geoip"


@define
class UserAgentRule(UniproxyBasicRule):
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(UniproxyBasicRule):
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(UniproxyBasicRule):
    type: Literal["process-name"] = "process-name"


@define
class AndRule(UniproxyBasicRule):
    type: Literal["and"] = "and"


@define
class OrRule(UniproxyBasicRule):
    type: Literal["or"] = "or"


@define
class NotRule(UniproxyBasicRule):
    type: Literal["not"] = "not"


@define
class SubnetRule(UniproxyBasicRule):
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(UniproxyBasicRule):
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(UniproxyBasicRule):
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(UniproxyBasicRule):
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(UniproxyBasicRule):
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(UniproxyBasicRule):
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(UniproxyBasicRule):
    type: Literal["script"] = "script"


@define
class CellularRadioRule(UniproxyBasicRule):
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(UniproxyBasicRule):
    type: Literal["device-name"] = "device-name"


@define
class DomainSetRule(UniproxyBasicRule):
    type: Literal["domain-set"] = "domain-set"


@define
class RuleSetRule(UniproxyBasicRule):
    type: Literal["rule-set"] = "rule-set"
