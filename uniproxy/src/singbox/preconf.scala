package uniproxy.singbox

import uniproxy.singbox.dns.DnsServer
import uniproxy.singbox.outbounds.{BlockOutbound, DirectOutbound, DnsOutbound}
import uniproxy.singbox.route.Rule

object prefconf {

  /** ------------- Snippets for flag as tag ------------- */
  val TAG_DNS_OUTBOUND = "DNS" // hijack dns query into sing box dns system
  val TAG_DIRECT_OUTBOUND = "DIRECT"
  val TAG_BLOCK_OUTBOUND = "REJECT"

  val TAG_DNSSERVER_SYSTEM = "dns-system"
  val TAG_DNSSERVER_REJECT = "dns-reject"
  val TAG_DNSSERVER_FAKEIP = "dns-fakeip"

  /** ------------- Snippets for DNS Servers ------------- */
  val dns_server_system = DnsServer(
    tag = TAG_DNSSERVER_SYSTEM,
    address = "localhost",
    detour = Some(TAG_DIRECT_OUTBOUND),
  )
  val dns_server_reject =
    DnsServer(tag = TAG_DNSSERVER_REJECT, address = "rcode://success")
  val dns_server_fakeip =
    DnsServer(tag = TAG_DNSSERVER_FAKEIP, address = "fakeip")

  /** ------------- Snippets for Outbound ------------- */
  val out_direct = DirectOutbound(tag = TAG_DIRECT_OUTBOUND)
  val out_block = BlockOutbound(tag = TAG_BLOCK_OUTBOUND)
  val out_dns = DnsOutbound(tag = TAG_DNS_OUTBOUND)

  /** ------------- Snippets for Route rules ------------- */
  val rule_dns = Rule(outbound = TAG_DNS_OUTBOUND, protocol = Some("dns"))
  val rule_dns_bypass =
    Rule(
      outbound = TAG_DIRECT_OUTBOUND,
      protocol = Some("dns"),
    ) // bypass dns query
}
