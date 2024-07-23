from __future__ import annotations

from uniproxy.singbox.dns import DnsRule, DnsServer
from uniproxy.singbox.outbounds import BlockOutbound, DirectOutbound, DnsOutbound
from uniproxy.singbox.route import RemoteRuleSet, Rule

#### ------------- Snippets for flag as tag ------------- ####
TAG_DNS_OUTBOUND = "DNS"  # hijack dns query into sing box dns system
TAG_DIRECT_OUTBOUND = "DIRECT"
TAG_BLOCK_OUTBOUND = "REJECT"
TAG_AUTO_OUTBOUND = "Auto"
TAG_CDN_OUTBOUND = "CDN"


TAG_DNSSERVER_SYSTEM = "dns-system"
TAG_DNSSERVER_REJECT = "dns-reject"
TAG_DNSSERVER_FAKEIP = "dns-fakeip"

#### ------------- Snippets for DNS Servers ------------- ####
dns_server_system = DnsServer(
    tag=TAG_DNSSERVER_SYSTEM, address="127.0.0.1", detour=TAG_DIRECT_OUTBOUND
)
dns_server_reject = DnsServer(tag=TAG_DNSSERVER_REJECT, address="rcode://success")
dns_server_fakeip = DnsServer(tag=TAG_DNSSERVER_FAKEIP, address="fakeip")
dns_server_google = DnsServer(
    tag="dns-google",
    address="https://dns.google/dns-query",  # tls://8.8.8.8
    detour=TAG_AUTO_OUTBOUND,
    client_subnet="1.0.1.0",
)
#### ------------- Snippets for Outbound ------------- ####
out_direct = DirectOutbound(tag=TAG_DIRECT_OUTBOUND)
out_block = BlockOutbound(tag=TAG_BLOCK_OUTBOUND)

out_dns = DnsOutbound(tag=TAG_DNS_OUTBOUND)

out_wan = DirectOutbound(tag="out-wan", bind_interface="wan")
out_wanx = DirectOutbound(tag="out-wanx", bind_interface="wanx")

#### ------------- Snippets for Route rules ------------- ####
rule_dns = Rule(outbound=TAG_DNS_OUTBOUND, protocol="dns")
rule_dns_direct = Rule(outbound=TAG_DIRECT_OUTBOUND, protocol="dns")  # bypass dns query


#### ------------- Snippets for Route RuleSet ------------- ####
# rule_set_cloudflare = RemoteRuleSet(
#     tag="rs-geoip-cloudflare",
# )
# rule_set_cloudfront = RemoteRuleSet(
#     tag="rs-geoip-cloudfront",
# )
# rule_set_fastly = RemoteRuleSet(
#     tag="rs-geoip-fastly",
# )
# rule_set_akamai = RemoteRuleSet(
#     tag="rs-geoip-akamai",
# )

# Asia
rs_region_asia = {
    region: RemoteRuleSet(
        tag=f"rs-geoip-{region}",
        format="binary",
        url=f"https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-{region}.srs",
    )
    for region in ("cn", "hk", "tw", "sg", "jp")
}


#### ------------- Snippets for DNS Rules ------------- ####
dns_rule_private = DnsRule(
    server=dns_server_system,
    ip_is_private=True,
)
dns_rule_gfw = DnsRule(
    server=dns_server_fakeip,
    rule_set=(),
)
