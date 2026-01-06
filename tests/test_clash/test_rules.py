from __future__ import annotations

from uniproxy.clash.rules import IPCidrRule, make_rules_from_uniproxy
from uniproxy.rules import IPCidrRule as UniproxyIPCidrRule


def test_ip_rules_with_no_resolve():

    for nr in (True, False):
        uniproxy_rule = UniproxyIPCidrRule(
            matcher="10.0.0.0/8", policy="Proxy", no_resolve=nr
        )
        rule = make_rules_from_uniproxy(uniproxy_rule)[0]

        assert isinstance(rule, IPCidrRule)
        assert rule.no_resolve == uniproxy_rule.no_resolve
