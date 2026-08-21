from __future__ import annotations

from typing import Literal

from attrs import define

from .base import BaseBasicRule, BaseRule, ProtocolLike


@define(slots=False)
class _NoResoleMixin:
    no_resolve: bool | None = None


@define
class DomainRule(BaseBasicRule):
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(BaseBasicRule):
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(BaseBasicRule):
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(BaseBasicRule):
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(_NoResoleMixin, BaseBasicRule):
    type: Literal["ip-cidr"] = "ip-cidr"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class IPCidr6Rule(_NoResoleMixin, BaseBasicRule):
    type: Literal["ip-cidr6"] = "ip-cidr6"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


@define
class GeoIPRule(_NoResoleMixin, BaseBasicRule):
    type: Literal["geoip"] = "geoip"

    def __str__(self) -> str:
        if self.no_resolve:
            return f"{self.type.upper()},{self.matcher},{self.policy},no-resolve"
        else:
            return f"{self.type.upper()},{self.matcher},{self.policy}"


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
class RuleSetRule(BaseBasicRule):
    type: Literal["rule-set"] = "rule-set"


@define
class FinalRule(BaseRule):
    policy: ProtocolLike
    type: Literal["final"] = "final"

    def __str__(self) -> str:
        return f"MATCH,{self.policy}"


type _BasicRule = (
    DomainRule
    | DomainSuffixRule
    | DomainKeywordRule
    | IPCidrRule
    | IPCidr6Rule
    | GeoIPRule
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
    | RuleSetRule
    | DomainSetRule
)

type Rule = _BasicRule | FinalRule
