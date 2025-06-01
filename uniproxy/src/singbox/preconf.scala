package uniproxy.singbox

import uniproxy.singbox.dns.DnsServer.LocalDnsServer
import uniproxy.singbox.outbounds.DirectOutbound
import uniproxy.singbox.route.Rule
import uniproxy.singbox.typing.SniffProtocol

object prefconf {

  /** ------------- Snippets for flag as tag ------------- */
  val TAG_DIRECT_OUTBOUND = "DIRECT"
  val TAG_DNS_SERVER_LOCAL = "dns-local"

  /** ------------- Snippets for DNS Servers ------------- */
  val dns_server_local = LocalDnsServer(tag = TAG_DNS_SERVER_LOCAL)

  /** ------------- Snippets for Outbound ------------- */
  val out_direct = DirectOutbound(tag = TAG_DIRECT_OUTBOUND)

  /** ------------- Snippets for Route rules ------------- */
  // bypass dns query
  val rule_dns_hijack = Rule(outbound = TAG_DIRECT_OUTBOUND, protocol = Some(SniffProtocol.dns))

}
