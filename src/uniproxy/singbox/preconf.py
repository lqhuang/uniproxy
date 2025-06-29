from __future__ import annotations

from uniproxy.singbox.dns import LocalDnsServer
from uniproxy.singbox.outbounds import DirectOutbound
from uniproxy.singbox.route import Rule

#### ------------- Snippets for flag as tag ------------- ####
# TAG_DNS_OUTBOUND = "DNS"  # hijack dns query into sing box dns system
TAG_DIRECT_OUTBOUND = "DIRECT"
TAG_BLOCK_OUTBOUND = "REJECT"
TAG_DROP_OUTBOUND = "REJECT-DROP"

TAG_DNS_SERVER_SYSTEM = "dns-system"
TAG_DNS_SERVER_ROUTER = "dns-router"


#### ------------- Snippets for DNS Servers ------------- ####
dns_server_system = LocalDnsServer(
    tag=TAG_DNS_SERVER_SYSTEM, detour=TAG_DIRECT_OUTBOUND
)
# dns_server_reject = DnsServer(tag=TAG_DNSSERVER_REJECT, address="rcode://success")
# dns_server_fakeip = DnsServer(tag=TAG_DNSSERVER_FAKEIP, address="fakeip")

#### ------------- Snippets for Outbound ------------- ####
out_direct = DirectOutbound(tag=TAG_DIRECT_OUTBOUND)
# out_dns = DnsOutbound(tag=TAG_DNS_OUTBOUND)

#### ------------- Snippets for Route rules ------------- ####
# rule_dns = Rule(outbound=TAG_DNS_OUTBOUND, protocol="dns")
# rule_dns_bypass = Rule(outbound=TAG_DIRECT_OUTBOUND, protocol="dns")  # bypass dns query
