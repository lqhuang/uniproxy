from __future__ import annotations

from typing import Sequence

import re

from uniproxy.singbox.route_rules import RouteRule
from uniproxy.surge.rules import (
    DestPortRule,
    DomainKeywordRule,
    DomainRule,
    DomainSuffixRule,
    IPCidr6Rule,
    IPCidrRule,
    ProcessNameRule,
    SrcIPRule,
    SrcPortRule,
    SurgeRule,
)

ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::"

regex_ipv4 = re.compile(ipv4_pattern)
regex_ipv6 = re.compile(ipv6_pattern)


def make_rules_from_singbox(rule: RouteRule) -> list[SurgeRule]:
    policy = rule.outbound

    rules: list[SurgeRule] = []

    match rule.domain:
        case str(ip):
            rules.append(DomainRule(matcher=ip, policy=policy))
        case Sequence():
            for ip in rule.domain:
                rules.append(DomainRule(matcher=ip, policy=policy))
    match rule.domain_suffix:
        case str(ip):
            rules.append(DomainSuffixRule(matcher=ip, policy=policy))
        case Sequence():
            for ip in rule.domain_suffix:
                rules.append(DomainSuffixRule(matcher=ip, policy=policy))
    match rule.domain_keyword:
        case str(ip):
            rules.append(DomainKeywordRule(matcher=ip, policy=policy))
        case Sequence():
            for ip in rule.domain_keyword:
                rules.append(DomainKeywordRule(matcher=ip, policy=policy))

    match rule.ip_cidr:
        case str(ip):
            if regex_ipv4.match(ip):
                rules.append(IPCidrRule(matcher=ip, policy=policy))
            elif regex_ipv6.match(ip):
                rules.append(IPCidr6Rule(matcher=ip, policy=policy))
            else:
                raise ValueError(f"Invalid IP w/o CIDR: {ip}")
        case Sequence():
            for ip in rule.ip_cidr:
                if regex_ipv4.match(ip):
                    rules.append(IPCidrRule(matcher=ip, policy=policy))
                elif regex_ipv6.match(ip):
                    rules.append(IPCidr6Rule(matcher=ip, policy=policy))
                else:
                    raise ValueError(f"Invalid IP w/o CIDR: {ip}")

    match rule.port:
        case int(p):
            rules.append(DestPortRule(matcher=str(p), policy=policy))
        case Sequence():
            for p in rule.port:
                rules.append(DestPortRule(matcher=str(p), policy=policy))

    match rule.source_ip_cidr:
        case str(ip):
            if regex_ipv4.match(ip):
                rules.append(SrcIPRule(matcher=ip, policy=policy))
            elif regex_ipv6.match(ip):
                rules.append(SrcIPRule(matcher=ip, policy=policy))
            else:
                raise ValueError(f"Invalid IP w/o CIDR: {ip}")
        case Sequence():
            for ip in rule.source_ip_cidr:
                if regex_ipv4.match(ip):
                    rules.append(SrcIPRule(matcher=ip, policy=policy))
                elif regex_ipv6.match(ip):
                    rules.append(SrcIPRule(matcher=ip, policy=policy))
                else:
                    raise ValueError(f"Invalid IP w/o CIDR: {ip}")

    match rule.source_port:
        case int(p):
            rules.append(SrcPortRule(matcher=str(p), policy=policy))
        case Sequence():
            for p in rule.source_port:
                rules.append(SrcPortRule(matcher=str(p), policy=policy))

    match rule.process_name:
        case str(pn):
            rules.append(ProcessNameRule(matcher=pn, policy=policy))
        case Sequence():
            for pn in rule.process_name:
                rules.append(ProcessNameRule(matcher=pn, policy=policy))

    if rule.rule_set or rule.protocol:
        raise ValueError(
            "rule_set is not supported yet. Cannot convert to surge rules."
        )

    return rules
