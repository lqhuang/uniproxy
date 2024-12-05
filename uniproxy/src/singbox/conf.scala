package uniproxy
package singbox

import uniproxy.singbox.abc.{AbstractSingBox, InboundLike, OutboundLike}

import uniproxy.singbox.dns.DNS
import uniproxy.singbox.route.Route
import uniproxy.singbox.typing.LogLevel

/**
 * `sing-box` uses JSON for configuration files.
 *
 * Ref: https://sing-box.sagernet.org/configuration/
 */
case class SingBoxConfig(
  dns: DNS,
  inbounds: Seq[InboundLike],
  outbounds: Seq[OutboundLike],
  route: Route,
  log: Option[Log] = None,
  ntp: Option[NTP] = None,
  experimental: Option[Map[String, String]] = None,
) extends AbstractSingBox

/**
 * Ref: https://sing-box.sagernet.org/configuration/log/
 */
case class Log(
  /** Disable logging, no output after start. */
  disabled: Option[Boolean] = None,
  /** Log level. */
  level: Option[LogLevel] = None,
  /** Output file path. Will not write log to console after enable. */
  output: Option[String] = None,
  /** Add time to each line. */
  timestamp: Option[Boolean] = None,
) extends AbstractSingBox

/**
 * Built-in NTP client service.
 *
 * If enabled, it will provide time for protocols like TLS/Shadowsocks/VMess, which is
 * useful for environments where time synchronization is not possible.
 *
 * Ref: https://sing-box.sagernet.org/configuration/ntp/
 */
class NTP extends AbstractSingBox

/**
 * Ref: https://sing-box.sagernet.org/configuration/experimental/
 */
class Experimental(
  cache_file: Option[CacheFile] = None,
  clash_api: Option[Map[String, String]] = None,
  v2ray_api: Option[Map[String, String]] = None,
) extends AbstractSingBox

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
class CacheFile(
  path: Option[String] = None,
  cache_id: Option[String] = None,
  store_fakeip: Option[Boolean] = None,
  store_rdrc: Option[Boolean] = None,
  rdrc_timeout: Option[String] = None,
  enabled: Option[Boolean] = Some(true),
) extends AbstractSingBox
