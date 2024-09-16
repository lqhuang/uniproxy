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
dns_server_google_doh = DnsServer(
    tag="dns-google-doh",
    address="https://dns.google/dns-query",  # tls://8.8.8.8
    address_resolver=TAG_DNSSERVER_SYSTEM,
    detour=TAG_AUTO_OUTBOUND,
    client_subnet="1.0.1.0",
)
dns_server_aliyun = DnsServer(
    tag="dns-aliyun",
    address="223.5.5.5",
    detour=TAG_DIRECT_OUTBOUND,
)
dns_server_dnspod = DnsServer(
    tag="dns-dnspod",
    address="119.29.29.29",
    detour=TAG_DIRECT_OUTBOUND,
)
#### ------------- Snippets for Outbound ------------- ####
out_direct = DirectOutbound(tag=TAG_DIRECT_OUTBOUND)
out_block = BlockOutbound(tag=TAG_BLOCK_OUTBOUND)
out_dns = DnsOutbound(tag=TAG_DNS_OUTBOUND)

#### ------------- Snippets for Route rules ------------- ####
rule_dns = Rule(outbound=TAG_DNS_OUTBOUND, protocol="dns")
rule_dns_direct = Rule(outbound=TAG_DIRECT_OUTBOUND, protocol="dns")  # bypass dns query

#### ------------- Snippets for Route RuleSet ------------- ####
rs_geosite_gfw = RemoteRuleSet(
    tag="rs-geosite-gfw",
    format="binary",
    url="https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geosite/gfw.srs",
    download_detour="Auto",
)

rs_geoip_cdn = {
    vendor: RemoteRuleSet(
        tag=f"rs-geoip-{vendor}",
        format="binary",
        url=f"https://github.com/MetaCubeX/meta-rules-dat/raw/sing/geo/geoip/{vendor}.srs",
        download_detour="Auto",
    )
    for vendor in ("cloudflare", "cloudfront", "fastly")  # "akamai", "google"
}

# Site
rs_geosite_cn = {
    suffix: RemoteRuleSet(
        tag=f"rs-geosite-{suffix}",
        format="binary",
        url=f"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{suffix}.srs",
        download_detour="Auto",
    )
    for suffix in ("geolocation-cn", "cn")
}

#### ------------- Snippets for DNS Rules ------------- ####
dns_rule_private = DnsRule(
    server=dns_server_system,
    ip_is_private=True,
)
dns_rule_gfw = DnsRule(
    server=dns_server_fakeip,
    rule_set=(rs_geosite_gfw,),
    outbound=TAG_AUTO_OUTBOUND,
)
dns_rule_cn = DnsRule(
    server=dns_server_system,
    rule_set=tuple(rs_geosite_cn.values()),
    outbound=TAG_DIRECT_OUTBOUND,
)
