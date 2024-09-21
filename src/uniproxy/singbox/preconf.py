from __future__ import annotations

from uniproxy.singbox.dns import DnsServer
from uniproxy.singbox.outbounds import BlockOutbound, DirectOutbound, DnsOutbound
from uniproxy.singbox.route import Rule

#### ------------- Snippets for flag as tag ------------- ####
TAG_DNS_OUTBOUND = "DNS"  # hijack dns query into sing box dns system
TAG_DIRECT_OUTBOUND = "DIRECT"
TAG_BLOCK_OUTBOUND = "REJECT"

TAG_DNSSERVER_SYSTEM = "dns-system"
TAG_DNSSERVER_REJECT = "dns-reject"
TAG_DNSSERVER_FAKEIP = "dns-fakeip"

#### ------------- Snippets for DNS Servers ------------- ####
dns_server_system = DnsServer(
    tag=TAG_DNSSERVER_SYSTEM, address="localhost", detour=TAG_DIRECT_OUTBOUND
)
dns_server_reject = DnsServer(tag=TAG_DNSSERVER_REJECT, address="rcode://success")
dns_server_fakeip = DnsServer(tag=TAG_DNSSERVER_FAKEIP, address="fakeip")

#### ------------- Snippets for Outbound ------------- ####
out_direct = DirectOutbound(tag=TAG_DIRECT_OUTBOUND)
out_block = BlockOutbound(tag=TAG_BLOCK_OUTBOUND)
out_dns = DnsOutbound(tag=TAG_DNS_OUTBOUND)

#### ------------- Snippets for Route rules ------------- ####
rule_dns = Rule(outbound=TAG_DNS_OUTBOUND, protocol="dns")
rule_dns_bypass = Rule(outbound=TAG_DIRECT_OUTBOUND, protocol="dns")  # bypass dns query
