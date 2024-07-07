from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.base import BaseProtocol, BaseRule


@define
class DomainRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain"] = "domain"


@define
class StackedDomainRule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class StackedDomainSuffixRule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class StackedDomainKeywordRule(BaseRule):
    matchers: list[str]
    policy: str | BaseProtocol
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class StackedIPCidrRule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class IPCidr6Rule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class StackedIPCidr6Rule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class GeoIPRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["geoip"] = "geoip"


@define
class UserAgentRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["process-name"] = "process-name"


@define
class AndRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["and"] = "and"


@define
class OrRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["or"] = "or"


@define
class NotRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["not"] = "not"


@define
class SubnetRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["script"] = "script"


@define
class CellularRadioRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["device-name"] = "device-name"


@define
class FinalRule(BaseRule):
    policy: str | BaseProtocol
    matcher: None = None
    type: Literal["final"] = "final"
