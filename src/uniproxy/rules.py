from __future__ import annotations

from typing import Literal

from abc import ABC

from attrs import frozen

from uniproxy.base import BaseProtocol

RuleType = Literal[
    # Domain-based Rule
    "domain",
    "domain-suffix",
    "domain-keyword",
    "domain-set",
    # IP-based Rule
    "ip-cidr",
    "ip-cidr6",
    "geoip",
    # HTTP Rule
    "user-agent",
    "url-regex",
    # Process Rule
    "process-name",
    # Logical Rule
    "and",
    "or",
    "not",
    # Subnet Rule
    "subnet",
    # Miscellaneous Rule
    "dest-port",
    "src-port",
    "in-port",
    "src-ip",
    "protocol",
    "script",
    "cellular-radio",
    "device-name",
    # Ruleset
    "rule-set",
    # Final Rule
    "final",
]


@frozen
class BaseRule(ABC):
    type: RuleType
    matcher: str
    policy: str | BaseProtocol

    def __str__(self) -> str:
        return str(self.type)


@frozen
class DomainRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain"] = "domain"


@frozen
class StackedDomainRule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    type: Literal["domain"] = "domain"


@frozen
class DomainSuffixRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain-suffix"] = "domain-suffix"


@frozen
class StackedDomainSuffixRule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    type: Literal["domain-suffix"] = "domain-suffix"


@frozen
class DomainKeywordRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain-keyword"] = "domain-keyword"


@frozen
class StackedDomainKeywordRule(BaseRule):
    matchers: list[str]
    policy: str | BaseProtocol
    type: Literal["domain-keyword"] = "domain-keyword"


@frozen
class DomainSetRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["domain-set"] = "domain-set"


@frozen
class IPCidrRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr"] = "ip-cidr"


@frozen
class StackedIPCidrRule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr"] = "ip-cidr"


@frozen
class IPCidr6Rule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr6"] = "ip-cidr6"


@frozen
class StackedIPCidr6Rule(BaseRule):
    matcher: list[str]
    policy: str | BaseProtocol
    no_resolve: bool = True
    type: Literal["ip-cidr6"] = "ip-cidr6"


@frozen
class GeoIPRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["geoip"] = "geoip"


@frozen
class UserAgentRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["user-agent"] = "user-agent"


@frozen
class UrlRegexRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["url-regex"] = "url-regex"


@frozen
class ProcessNameRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["process-name"] = "process-name"


@frozen
class AndRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["and"] = "and"


@frozen
class OrRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["or"] = "or"


@frozen
class NotRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["not"] = "not"


@frozen
class SubnetRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["subnet"] = "subnet"


@frozen
class DestPortRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["dest-port"] = "dest-port"


@frozen
class SrcPortRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["src-port"] = "src-port"


@frozen
class InPortRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["in-port"] = "in-port"


@frozen
class SrcIPRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["src-ip"] = "src-ip"


@frozen
class ProtocolRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["protocol"] = "protocol"


@frozen
class ScriptRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["script"] = "script"


@frozen
class CellularRadioRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["cellular-radio"] = "cellular-radio"


@frozen
class DeviceNameRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["device-name"] = "device-name"


@frozen
class RuleSetRule(BaseRule):
    matcher: str
    policy: str | BaseProtocol
    type: Literal["rule-set"] = "rule-set"


@frozen
class FinalRule(BaseRule):
    policy: str | BaseProtocol
    matcher: None = None
    type: Literal["final"] = "final"
