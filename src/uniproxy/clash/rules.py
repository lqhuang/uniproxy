from __future__ import annotations

from typing import Literal

import gc

from attrs import define, fields

from uniproxy.providers import RuleProvider as UniproxyRuleProvider
from uniproxy.rules import UniproxyRule

from .base import BaseProtocol, BaseRule, ProtocolLike
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


@define
class DomainRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain"] = "domain"


@define
class DomainSuffixRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain-suffix"] = "domain-suffix"


@define
class DomainKeywordRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain-keyword"] = "domain-keyword"


@define
class DomainSetRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["domain-set"] = "domain-set"


@define
class IPCidrRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["ip-cidr"] = "ip-cidr"


@define
class IPCidr6Rule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["ip-cidr6"] = "ip-cidr6"


@define
class GeoIPRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["geoip"] = "geoip"


@define
class UserAgentRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["user-agent"] = "user-agent"


@define
class UrlRegexRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["url-regex"] = "url-regex"


@define
class ProcessNameRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["process-name"] = "process-name"


@define
class AndRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["and"] = "and"


@define
class OrRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["or"] = "or"


@define
class NotRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["not"] = "not"


@define
class SubnetRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["subnet"] = "subnet"


@define
class DestPortRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["dest-port"] = "dest-port"


@define
class SrcPortRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["src-port"] = "src-port"


@define
class InPortRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["in-port"] = "in-port"


@define
class SrcIPRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["src-ip"] = "src-ip"


@define
class ProtocolRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["protocol"] = "protocol"


@define
class ScriptRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["script"] = "script"


@define
class CellularRadioRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["cellular-radio"] = "cellular-radio"


@define
class DeviceNameRule(BaseRule):
    matcher: str
    policy: str | ProtocolLike
    type: Literal["device-name"] = "device-name"


@define
class RuleSetRule(BaseRule):
    matcher: str | RuleProvider
    policy: str | ProtocolLike
    type: Literal["rule-set"] = "rule-set"
