import scala.collection.immutable.Map

import uniproxy.typing.{ALPN, ShadowsocksCipher, VmessCipher}

import uniproxy.surge.abc.AbstractProtocol
import uniproxy.surge.typing.ProtocolType

import com.comcast.ip4s.Host

case class WireguardPeer(
  endpoint: String,
  publicKey: String,
  allowedIps: Seq[String],
  clientId: Option[(Int, Int, Int)] = None,
) {
  def toMap: Map[String, Any] = {
    Map(
      "public-key" -> publicKey,
      "allowed-ips" -> allowedIps,
      "endpoint" -> endpoint,
      "client-id" -> clientId,
    ).collect { case (k, v) if v != null => k -> v }
  }
}

case class WireguardSection(
  name: String,
  privateKey: String,
  peer: WireguardPeer,
  selfIp: Option[Host] = None,
  selfIpV6: Option[Host] = None,
  dnsServer: Option[Seq[Host]] = None,
  preferIpv6: Option[Boolean] = None,
  mtu: Option[Int] = None,
  `type`: String = "wireguard",
) {
  // def toMap: Map[String, Any] = {
  //   Map(
  //     "private-key" -> privateKey,
  //     "peer" -> peer.toMap,
  //     "self-ip" -> selfIp,
  //     "self-ip-v6" -> selfIpV6,
  //     "dns-server" -> dnsServer,
  //     "prefer-ipv6" -> preferIpv6,
  //     "mtu" -> mtu
  //   ).collect { case (k, v) if v != null => k -> v }
  // }
}

sealed class SurgeProtocol(val `type`: String) {
  // def fromUniproxy(
  //     protocol: UniproxyProtocol,
  //     kwargs: Map[String, Any] = Map()
  // ): SurgeProtocol
  // def toUniproxy(kwargs: Map[String, Any] = Map()): UniproxyProtocol

  case class HttpProtocol(
    username: Option[String] = None,
    password: Option[String] = None,
    // tls: Option[SurgeTLS] = None,
    tfo: Boolean = false,
    alwaysUseConnect: Option[Boolean] = None,
  ) extends SurgeProtocol("http") {

    // def fromUniproxy(
    //     protocol: UniproxyHttpProtocol,
    //     kwargs: Map[String, Any] = Map()
    // ): HttpProtocol = {
    //   val tls = protocol.tls.map(SurgeTLS.fromUniproxy)
    //   HttpProtocol(
    //     username = protocol.username,
    //     password = protocol.password,
    //     tls = tls,
    //     alwaysUseConnect = Some(false)
    //   )
    // }

    // def toUniproxy(kwargs: Map[String, Any] = Map()): UniproxyHttpProtocol = {
    //   UniproxyHttpProtocol(
    //     name = kwargs("name").asInstanceOf[String],
    //     server = kwargs("server").asInstanceOf[String],
    //     port = kwargs("port").asInstanceOf[Int],
    //     username = username,
    //     password = password,
    //     tls = tls.map(_.toUniproxy)
    //   )
    // }
  }

  case class Socks5Protocol(
    username: Option[String] = None,
    password: Option[String] = None,
    // tls: Option[SurgeTLS] = None,
    udpRelay: Option[Boolean] = None,
  ) extends SurgeProtocol("socks5") {

    // def fromUniproxy(
    //     protocol: UniproxySocks5Protocol,
    //     kwargs: Map[String, Any] = Map()
    // ): Socks5Protocol = {
    //   val tls = protocol.tls.map(SurgeTLS.fromUniproxy)
    //   Socks5Protocol(
    //     username = protocol.username,
    //     password = protocol.password,
    //     tls = tls,
    //     udpRelay = Some(protocol.network != "tcp"),0
    //     `type` = if (tls.isDefined) "socks5-tls" else "socks5"
    //   )
    // }

    // def toUniproxy(kwargs: Map[String, Any] = Map()): UniproxySocks5Protocol = {
    //   UniproxySocks5Protocol(
    //     name = kwargs("name").asInstanceOf[String],
    //     server = kwargs("server").asInstanceOf[String],
    //     port = kwargs("port").asInstanceOf[Int],
    //     username = username,
    //     password = password,
    //     tls = tls.map(_.toUniproxy)
    //   )
    // }
  }

  case class ShadowsocksProtocol(
    password: String,
    encryptMethod: ShadowsocksCipher,
    udpRelay: Option[Boolean] = None,
    obfs: Option[String] = None,
    obfsHost: Option[String] = None,
    obfsUri: Option[String] = None,
    ecn: Option[Boolean] = None,
  ) extends SurgeProtocol("ss") {

    // def fromUniproxy(
    //     protocol: UniproxyShadowsocksProtocol,
    //     kwargs: Map[String, Any] = Map()
    // ): ShadowsocksProtocol = {
    //   ShadowsocksProtocol(
    //     password = protocol.password,
    //     encryptMethod = protocol.method,
    //     udpRelay = Some(protocol.network != "tcp"),
    //     obfs = protocol.obfs,
    //     obfsHost = protocol.obfsHost,
    //     obfsUri = protocol.obfsUri,
    //     ecn = protocol.ecn
    //   )
    // }

    // def toUniproxy(
    //     kwargs: Map[String, Any] = Map()
    // ): UniproxyShadowsocksProtocol = {
    //   UniproxyShadowsocksProtocol(
    //     name = kwargs("name").asInstanceOf[String],
    //     server = kwargs("server").asInstanceOf[String],
    //     port = kwargs("port").asInstanceOf[Int],
    //     password = password,
    //     method = encryptMethod,
    //     network = if (udpRelay.getOrElse(false)) "udp" else "tcp",
    //     obfs = obfs,
    //     obfsHost = obfsHost,
    //     obfsUri = obfsUri,
    //     ecn = ecn
    //   )
    // }
  }

  case class VmessTransport(
    path: Option[String] = None,
    headers: Option[Map[String, String]] = None,
    vmessAead: Option[Boolean] = None,
    `type`: String = "ws",
  ) {
    // override def toString: String = {
    //   val wsHeaders =
    //     headers.map(_.map { case (k, v) => s"$k:$v" }.mkString("|")).orNull
    //   val opts = Map(
    //     "ws" -> "true",
    //     "ws-path" -> path.orNull,
    //     "ws-headers" -> wsHeaders,
    //     "vmess-aead" -> vmessAead.map(_.toString.toLowerCase).orNull
    //   )
    //   opts.collect { case (k, v) if v != null => s"$k=$v" }.mkString(", ")
    // }
  }

  case class VmessProtocol(
    username: String,
    encryptMethod: Option[VmessCipher] = None,
    // tls: Option[SurgeTLS] = None,
    transport: Option[VmessTransport] = None,
  ) extends SurgeProtocol("vmess") {
    // def fromUniproxy(
    //     protocol: UniproxyVmessProtocol,
    //     kwargs: Map[String, Any] = Map()
    // ): VmessProtocol = {
    //   val encryptMethod = protocol.security match {
    //     case "chacha20-ietf-poly1305" | "aes-128-gcm" => Some(protocol.security)
    //     case _                                        => None
    //   }
    //   VmessProtocol(
    //     username = protocol.uuid,
    //     encryptMethod = encryptMethod,
    //     tls = protocol.tls.map(SurgeTLS.fromUniproxy),
    //     transport = protocol.transport.map(t =>
    //       VmessTransport(path = t.path, headers = t.headers)
    //     )
    //   )
    // }

    // def toUniproxy(kwargs: Map[String, Any] = Map()): UniproxyVmessProtocol = {
    //   UniproxyVmessProtocol(
    //     name = kwargs("name").asInstanceOf[String],
    //     server = kwargs("server").asInstanceOf[String],
    //     port = kwargs("port").asInstanceOf[Int],
    //     uuid = username,
    //     security = encryptMethod.orNull,
    //     tls = tls.map(_.toUniproxy),
    //     transport = transport.map(t =>
    //       UniproxyTransport(path = t.path, headers = t.headers)
    //     )
    //   )
    // }
  }

  case class TrojanProtocol(
    password: String,
    // tls: Option[SurgeTLS] = None,
    udpRelay: Option[Boolean] = None,
  ) extends SurgeProtocol("trojan") {
    // def fromUniproxy(
    //     protocol: UniproxyTrojanProtocol,
    //     kwargs: Map[String, Any] = Map()
    // ): TrojanProtocol = {
    //   TrojanProtocol(
    //     password = protocol.password,
    //     tls = protocol.tls.map(SurgeTLS.fromUniproxy),
    //     udpRelay = Some(protocol.network != "tcp")
    //   )
    // }

    // def toUniproxy(kwargs: Map[String, Any] = Map()): UniproxyTrojanProtocol = {
    //   UniproxyTrojanProtocol(
    //     name = kwargs("name").asInstanceOf[String],
    //     server = kwargs("server").asInstanceOf[String],
    //     port = kwargs("port").asInstanceOf[Int],
    //     password = password,
    //     tls = tls.map(_.toUniproxy),
    //     network = if (udpRelay.getOrElse(false)) "udp" else "tcp"
    //   )
    // }
  }

  case class TuicProtocol(
    token: String,
    alpn: Option[ALPN] = None,
    // tls: Option[SurgeTLS] = None,
    udpRelay: Option[Boolean] = Some(true),
  ) extends SurgeProtocol("tuic") {
    // def fromUniproxy(
    //     protocol: UniproxyTuicProtocol,
    //     kwargs: Map[String, Any] = Map()
    // ): TuicProtocol = {
    //   TuicProtocol(
    //     token = protocol.token,
    //     alpn = protocol.tls.flatMap(_.alpn.headOption),
    //     tls = protocol.tls.map(SurgeTLS.fromUniproxy),
    //     udpRelay = Some(true)
    //   )
    // }

    // def toUniproxy(kwargs: Map[String, Any] = Map()): UniproxyTuicProtocol = {
    //   UniproxyTuicProtocol(
    //     name = kwargs("name").asInstanceOf[String],
    //     server = kwargs("server").asInstanceOf[String],
    //     port = kwargs("port").asInstanceOf[Int],
    //     token = token,
    //     tls = tls.map(_.toUniproxy)
    //   )
    // }
  }

  case class WireguardProtocol(
    sectionName: Either[String, WireguardSection],
  ) extends SurgeProtocol("wireguard") {
    // def fromUniproxy(
    //     protocol: UniproxyWireguardProtocol,
    //     kwargs: Map[String, Any] = Map()
    // ): WireguardProtocol = {
    //   WireguardProtocol(
    //     sectionName = Left(protocol.sectionName)
    //   )
    // }

    // def toUniproxy(
    //     kwargs: Map[String, Any] = Map()
    // ): UniproxyWireguardProtocol = {
    //   UniproxyWireguardProtocol(
    //     name = kwargs("name").asInstanceOf[String],
    //     sectionName = sectionName.left.getOrElse("")
    //   )
    // }
  }

}

enum Protocol(`type`: ProtocolType) {

  case HttpProtocol extends Protocol("http")

  // private val mapper: Map[String, SurgeProtocol] = Map(
  //   "http" -> HttpProtocol(),
  //   "https" -> HttpProtocol(),
  //   "socks5" -> Socks5Protocol(),
  //   "socks5-tls" -> Socks5Protocol(),
  //   "shadowsocks" -> ShadowsocksProtocol("", ShadowsocksCipher("")),
  //   "vmess" -> VmessProtocol(""),
  //   "trojan" -> TrojanProtocol(""),
  //   "tuic" -> TuicProtocol(""),
  //   "wireguard" -> WireguardProtocol(Left(""))
  // )

  // def makeProtocolFromUniproxy(
  //     protocol: UniproxyProtocol,
  //     kwargs: Map[String, Any] = Map()
  // ): SurgeProtocol = {
  //   mapper.get(protocol.`type`) match {
  //     case Some(proto) => proto.fromUniproxy(protocol, kwargs)
  //     case None =>
  //       throw new IllegalArgumentException(
  //         s"Unknown protocol type '${protocol.`type`}' when transforming uniproxy protocol to surge protocol"
  //       )
  //   }
  // }
}
