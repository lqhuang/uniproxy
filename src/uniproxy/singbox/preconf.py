from __future__ import annotations

from uniproxy.singbox.dns import (
    FakeIPDnsServer,
    H3DnsServer,
    HttpsDnsServer,
    LocalDnsServer,
    TlsDnsServer,
    UdpDnsServer,
)
from uniproxy.singbox.http_clients import Http2Client
from uniproxy.singbox.outbounds import DirectOutbound
from uniproxy.singbox.route import HijackDnsRule, SniffRule

#### ------------- Snippets for flag as tag ------------- ####
# TAG_DNS_OUTBOUND = "DNS"  # hijack dns query into sing box dns system
TAG_DIRECT_OUTBOUND = "DIRECT"
TAG_BLOCK_OUTBOUND = "REJECT"
TAG_DROP_OUTBOUND = "REJECT-DROP"

TAG_DNS_SERVER_SYSTEM = "dns-system"
TAG_DNS_SERVER_FAKEIP = "dns-fakeip"

TAG_DEFAULT_HTTP_CLIENT = "http-client-default"

#### ------------- Snippets for DNS Servers ------------- ####
dns_server_system = LocalDnsServer(tag=TAG_DNS_SERVER_SYSTEM)
dns_server_fakeip = FakeIPDnsServer(tag=TAG_DNS_SERVER_FAKEIP)
# dns_server_reject = DnsServer(tag=TAG_DNSSERVER_REJECT, address="rcode://success")

dns_server_google_udp = UdpDnsServer(tag="dns-google-udp", server="8.8.8.8")
dns_server_google_tls = TlsDnsServer(tag="dns-google-tls", server="8.8.8.8")
dns_server_google_https = HttpsDnsServer(tag="dns-google-https", server="8.8.8.8")
dns_server_google_h3 = H3DnsServer(tag="dns-google-h3", server="8.8.8.8")

# fmt: off
dns_server_cloudflare_udp = UdpDnsServer(tag="dns-cloudflare-udp", server="1.1.1.1")
dns_server_cloudflare_tls = TlsDnsServer(tag="dns-cloudflare-tls", server="1.1.1.1")
dns_server_cloudflare_https = HttpsDnsServer(tag="dns-cloudflare-https", server="1.1.1.1")
dns_server_cloudflare_h3 = H3DnsServer(tag="dns-cloudflare-h3", server="1.1.1.1")
# fmt: on

#### ------------- Snippets for Outbound ------------- ####
out_direct = DirectOutbound(tag=TAG_DIRECT_OUTBOUND)

#### ------------- Snippets for Route Rules ------------- ####
# rule_dns = Rule(outbound=TAG_DNS_OUTBOUND, protocol="dns")
# rule_dns_bypass = Rule(outbound=TAG_DIRECT_OUTBOUND, protocol="dns")  # bypass dns query
rule_sniff = SniffRule()
rule_hijack_dns = HijackDnsRule()

#### ------------- Snippets for Http Clients ------------- ####
hc_default = Http2Client(tag=TAG_DEFAULT_HTTP_CLIENT, version=2)
