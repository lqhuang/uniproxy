from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.base import BaseRule, BaseRuleProvider, ProtocolLike


@define
class UniproxyRule(BaseRule): ...


@define
class DomainRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain"] = "domain"


@define
class DomainGroupRule(UniproxyRule):
    matcher: list[str]
    policy: ProtocolLike | str
    type: Literal["domain-group"] = "domain-group"


@define
class DomainSuffixRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainSuffixGroupRule(UniproxyRule):
    matcher: list[str]
    policy: ProtocolLike | str
    type: Literal["domain-suffix-group"] = "domain-suffix-group"


@define
class DomainKeywordRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainKeywordGroupRule(UniproxyRule):
    matcher: list[str]
    policy: ProtocolLike | str
    type: Literal["domain-keyword-group"] = "domain-keyword-group"


@define
class IPCidrRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class IPCidrGroupRule(UniproxyRule):
    matcher: list[str]
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr-group"] = "ip-cidr-group"


@define
class IPCidr6Rule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class IPCidr6GroupRule(UniproxyRule):
    matcher: list[str]
    policy: ProtocolLike | str
    no_resolve: bool | None = None
    type: Literal["ip-cidr6-group"] = "ip-cidr6-group"


@define
class GeoIPRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["geoip"] = "geoip"


@define
class UserAgentRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["process-name"] = "process-name"


@define
class AndRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["and"] = "and"


@define
class OrRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["or"] = "or"


@define
class NotRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["not"] = "not"


@define
class SubnetRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["script"] = "script"


@define
class CellularRadioRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(UniproxyRule):
    matcher: str
    policy: ProtocolLike | str
    type: Literal["device-name"] = "device-name"


@define
class FinalRule(UniproxyRule):
    matcher: None = None
    policy: ProtocolLike | str = None  # type: ignore
    type: Literal["final"] = "final"

    def __attrs_post_init__(self):
        if self.policy is None:
            raise ValueError("FinalRule must have a policy, cannot be None")


@define
class DomainSetRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike | str
    type: Literal["domain-set"] = "domain-set"


@define
class RuleSetRule(UniproxyRule):
    matcher: str | BaseRuleProvider
    policy: ProtocolLike | str
    type: Literal["rule-set"] = "rule-set"
