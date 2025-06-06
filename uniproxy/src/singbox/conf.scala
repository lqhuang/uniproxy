package uniproxy
package singbox

import upickle.default.ReadWriter

import uniproxy.singbox.abc.AbstractSingBox
import uniproxy.singbox.dns.DNS
import uniproxy.singbox.route.Route
import uniproxy.singbox.typing.LogLevel
import uniproxy.singbox.Inbound
import uniproxy.singbox.Outbound
import uniproxy.singbox.Outbound.outboundRW

/**
 * `sing-box` uses JSON for configuration files.
 *
 * Ref: https://sing-box.sagernet.org/configuration/
 */
case class SingBoxConfig(
  dns: DNS,
  inbounds: Seq[Inbound],
  outbounds: Seq[Outbound],
  route: Route,
  log: Option[Log] = None,
  ntp: Option[NTP] = None,
  experimental: Option[Map[String, String]] = None,
) extends AbstractSingBox derives ReadWriter

/**
 * Ref: https://sing-box.sagernet.org/configuration/log/
 *
 * @param disabled Disable logging, no output after start.
 * @param level Log level.
 * @param output Output file path. Will not write log to console after enable.
 * @param timestamp Add time to each line.
 */
case class Log(
  disabled: Option[Boolean] = None,
  level: Option[LogLevel] = None,
  output: Option[String] = None,
  timestamp: Option[Boolean] = None,
) extends AbstractSingBox derives ReadWriter

/**
 * Built-in NTP client service.
 *
 * If enabled, it will provide time for protocols like TLS/Shadowsocks/VMess,
 * which is useful for environments where time synchronization is not possible.
 *
 * Ref: https://sing-box.sagernet.org/configuration/ntp/
 */
case class NTP() extends AbstractSingBox derives ReadWriter

/** Ref: https://sing-box.sagernet.org/configuration/experimental/ */
case class Experimental(
  cache_file: Option[CacheFile] = None,
  clash_api: Option[Map[String, String]] = None,
  v2ray_api: Option[Map[String, String]] = None,
) extends AbstractSingBox derives ReadWriter

/**
 * Ref: https://sing-box.sagernet.org/configuration/experimental/cache-file/
 *
 * ```json
 * {
 *   "enabled": true,
 *   "path": "",
 *   "cache_id": "",
 *   "store_fakeip": false,
 *   "store_rdrc": false,
 *   "rdrc_timeout": ""
 * }
 * ```
 */
case class CacheFile(
  path: Option[String] = None,
  cache_id: Option[String] = None,
  store_fakeip: Option[Boolean] = None,
  store_rdrc: Option[Boolean] = None,
  rdrc_timeout: Option[String] = None,
  enabled: Option[Boolean] = Some(true),
) extends AbstractSingBox derives ReadWriter
