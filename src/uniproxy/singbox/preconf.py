from __future__ import annotations

from uniproxy.singbox.dns import FakeIPDnsServer, H3DnsServer, LocalDnsServer
from uniproxy.singbox.outbounds import DirectOutbound
from uniproxy.singbox.route import HijackDnsRule, SniffRule

#### ------------- Snippets for flag as tag ------------- ####
# TAG_DNS_OUTBOUND = "DNS"  # hijack dns query into sing box dns system
TAG_DIRECT_OUTBOUND = "DIRECT"
TAG_BLOCK_OUTBOUND = "REJECT"
TAG_DROP_OUTBOUND = "REJECT-DROP"

TAG_DNS_SERVER_SYSTEM = "dns-system"
TAG_DNS_SERVER_FAKEIP = "dns-fakeip"

#### ------------- Snippets for DNS Servers ------------- ####
dns_server_system = LocalDnsServer(tag=TAG_DNS_SERVER_SYSTEM)
dns_server_fakeip = FakeIPDnsServer(tag=TAG_DNS_SERVER_FAKEIP)
# dns_server_reject = DnsServer(tag=TAG_DNSSERVER_REJECT, address="rcode://success")

dns_server_google_h3 = H3DnsServer(tag="dns-google-h3", server="8.8.8.8")
dns_server_cloudflare_h3 = H3DnsServer(tag="dns-cloudflare-h3", server="1.1.1.1")

#### ------------- Snippets for Outbound ------------- ####
out_direct = DirectOutbound(tag=TAG_DIRECT_OUTBOUND)
# out_dns = DnsOutbound(tag=TAG_DNS_OUTBOUND)

#### ------------- Snippets for Route rules ------------- ####
# rule_dns = Rule(outbound=TAG_DNS_OUTBOUND, protocol="dns")
# rule_dns_bypass = Rule(outbound=TAG_DIRECT_OUTBOUND, protocol="dns")  # bypass dns query
rule_sniff = SniffRule()
rule_hijack_dns = HijackDnsRule()
