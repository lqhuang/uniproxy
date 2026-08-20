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
from uniproxy.singbox.route_rules import HijackDnsRule, SniffRule
from uniproxy.singbox.shared import OutboundTLS

#### ------------- Snippets for flag as tag ------------- ####
TAG_DIRECT_OUTBOUND = "DIRECT"
TAG_BLOCK_OUTBOUND = "REJECT"
TAG_DROP_OUTBOUND = "REJECT-DROP"

TAG_DNS_SERVER_SYSTEM = "dns-system"
TAG_DNS_SERVER_FAKEIP = "dns-fakeip"

TAG_DEFAULT_HTTP_CLIENT = "http-client-default"

#### ------------- Snippets for DNS Servers ------------- ####
DNS_SERVER_SYSTEM = LocalDnsServer(tag=TAG_DNS_SERVER_SYSTEM)
# DNS_SERVER_REJECT = DnsServer(tag=TAG_DNSSERVER_REJECT, address="rcode://success")

# Previous range:
#
# - inet4_range="172.27.0.0/16"
# - inet6_range="fc01:7227::/32"
#
# To avoid [The Local Network Access permission prompt](https://developer.chrome.com/blog/local-network-access)
#
# New candidate ranges:
#
# - IPv4:
#   - 192.0.2.0/24 (TEST-NET-1)
#   - 198.51.100.0/24 (TEST-NET-2)
#   - 203.0.113.0/24 (TEST-NET-3)
#   - 240.0.0.0/4 (Reserved for Future Use)
#
# - IPv6
#   - 2001:2::/48 (Used for benchmarking IPv6)
#   - 2620:4f:8000::/48 (Blackhole servers with the traditional authoritative zones configured)
#   - 2001:4:112::/48 (Blackhole servers for the new blackholing approach involving DNAME records to empty.as112.arpa)
#   - 2001:db8::/32 (This prefix is used in documentation, anywhere an example IPv6 address is given or model networking scenarios are described.)
#
DNS_SERVER_FAKEIP = FakeIPDnsServer(
    tag=TAG_DNS_SERVER_FAKEIP, inet4_range="240.0.0.0/4", inet6_range="2001:db8::/32"
)


DNS_SERVER_GOOGLE_UDP = UdpDnsServer(tag="dns-google-udp", server="8.8.8.8")
DNS_SERVER_GOOGLE_TLS = TlsDnsServer(tag="dns-google-tls", server="8.8.8.8")
DNS_SERVER_GOOGLE_HTTPS = HttpsDnsServer(
    tag="dns-google-https",
    server="8.8.8.8",
    tls=OutboundTLS(enabled=True, server_name="dns.google", min_version="1.3"),
)
DNS_SERVER_GOOGLE_H3 = H3DnsServer(
    tag="dns-google-h3",
    server="8.8.8.8",
    tls=OutboundTLS(enabled=True, server_name="dns.google", min_version="1.3"),
)


DNS_SERVER_CLOUDFLARE_UDP = UdpDnsServer(
    tag="dns-cloudflare-udp", server="1.1.1.1", server_port=53
)
DNS_SERVER_CLOUDFLARE_TLS = TlsDnsServer(
    tag="dns-cloudflare-tls",
    server="1.1.1.1",
    tls=OutboundTLS(enabled=True, server_name="cloudflare-dns.com", min_version="1.3"),
)
DNS_SERVER_CLOUDFLARE_HTTPS = HttpsDnsServer(
    tag="dns-cloudflare-https",
    server="1.1.1.1",
    tls=OutboundTLS(enabled=True, server_name="cloudflare-dns.com", min_version="1.3"),
)
DNS_SERVER_CLOUDFLARE_H3 = H3DnsServer(
    tag="dns-cloudflare-h3",
    server="1.1.1.1",
    tls=OutboundTLS(enabled=True, server_name="cloudflare-dns.com", min_version="1.3"),
)


#### ------------- Snippets for Outbound ------------- ####
OUT_DIRECT = DirectOutbound(tag=TAG_DIRECT_OUTBOUND)

#### ------------- Snippets for Route Rules ------------- ####
# RULE_DNS = Rule(outbound=TAG_DNS_OUTBOUND, protocol="dns")
# RULE_DNS_BYPASS = Rule(outbound=TAG_DIRECT_OUTBOUND, protocol="dns")  # bypass dns query
RULE_SNIFF = SniffRule()
RULE_HIJACK_DNS = HijackDnsRule()

#### ------------- Snippets for Http Clients ------------- ####
HC_DEFAULT = Http2Client(tag=TAG_DEFAULT_HTTP_CLIENT, version=2)
