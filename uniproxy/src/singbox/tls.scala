package uniproxy.singbox.tls

import com.comcast.ip4s.{Hostname, Port}

import uniproxy.typing.ALPN

import uniproxy.singbox.typing.TLSVersion
import uniproxy.singbox.abc.AbstractSingBox

type PathLike = String

case class ExternalAccount(
  /** The key identifier. */
  key_id: Option[String] = None,
  /** The MAC key. */
  mac_key: Option[String] = None,
) extends AbstractSingBox

enum DNS01Challenge(
  provider: "cloudflare" | "alidns",
) {
  case CloudflareDNS01Challenge(api_token: String) extends DNS01Challenge("cloudflare")
  case AliDNS01Challenge(
    access_key_id: String,
    access_key_secret: String,
    region_id: String,
  ) extends DNS01Challenge("alidns")
}

case class ACME(
  /**
   * List of [[domain]].
   *
   * ACME will be disabled if empty.
   */
  domain: Option[Seq[Hostname]] = None,
  /**
   * The directory to store ACME data.
   *
   * `$XDG_DATA_HOME/certmagic|$HOME/.local/share/certmagic` will be used if
   * empty.
   */
  data_directory: Option[String] = None,
  /**
   * Server name to use when choosing a certificate if the ClientHello's
   * ServerName field is empty.
   */
  default_server_name: Option[Hostname] = None,
  /**
   * The email address to use when creating or selecting an existing ACME server
   * account
   */
  email: Option[String] = None,
  /**
   * The ACME CA provider to use.
   *
   * | Value                   | Provider      |
   * |:------------------------|:--------------|
   * | `letsencrypt (default)` | Let's Encrypt |
   * | `zerossl`               | ZeroSSL       |
   * | `https://...`           | Custom        |
   */
  provider: Option["letsencrypt" | "zerossl" | String] = None,
  /** Disable all HTTP challenges. */
  disable_http_challenge: Option[Boolean] = None,
  /** Disable all TLS-ALPN challenges. */
  disable_tls_alpn_challenge: Option[Boolean] = None,
  /**
   * The alternate port to use for the ACME HTTP challenge; if non-empty, this
   * port will be used instead of 80 to spin up a listener for the HTTP
   * challenge.
   */
  alternative_http_port: Option[Port] = None,
  /**
   * The alternate port to use for the ACME TLS-ALPN challenge; the system must
   * forward 443 to this port for challenge to succeed.
   */
  alternative_tls_port: Option[Port] = None,
  /**
   * EAB (External Account Binding) contains information necessary to bind or
   * map an ACME account to some other account known by the CA.
   *
   * External account bindings are "used to associate an ACME account with an
   * existing account in a non-ACME system, such as a CA customer database.
   *
   * To enable ACME account binding, the CA operating the ACME server needs to
   * provide the ACME client with a MAC key and a key identifier, using some
   * mechanism outside of ACME.
   */
  external_account: Option[ExternalAccount] = None,
  /**
   * ACME DNS01 challenge field. If configured, other challenge methods will be
   * disabled.
   */
  dns01_challenge: Option[DNS01Challenge] = None,
)

/**
 * ECH (Encrypted Client Hello) is a TLS extension that allows a client to
 * encrypt the first part of its ClientHello message.
 *
 * The ECH key and configuration can be generated by `sing-box generate
 * ech-keypair [--pq-signature-schemes-enabled]`.
 *
 * @param enabled
 * @param pq_signature_schemes_enabled
 * @param dynamic_record_sizing_disabled
 * @param key
 * @param key_path
 */
case class ECH(
  enabled: Option[Boolean] = None,
  pq_signature_schemes_enabled: Option[Boolean] = None,
  dynamic_record_sizing_disabled: Option[Boolean] = None,
  key: Option[Seq[String]] = None,
  key_path: Option[String] = None,
)

/**
 * utls
 *
 * **Client only**
 *
 * uTLS is a fork of "crypto/tls", which provides ClientHello fingerprinting
 * resistance.
 *
 * Available fingerprint values:
 *
 *   - chrome
 *   - firefox
 *   - edge
 *   - safari
 *   - 360
 *   - qq
 *   - ios
 *   - android
 *   - random
 *   - randomized
 *
 * Chrome fingerprint will be used if empty.
 *
 * @param enabled
 * @param fingerprint
 */
case class UTLS(
  enabled: Option[Boolean] = None,
  fingerprint: Option[String] = None,
)

abstract class BaseTLS extends AbstractSingBox

/**
 * Inbound TLS
 * ```json
 * {
 *   "enabled": true,
 *   "server_name": "",
 *   "alpn": [],
 *   "min_version": "",
 *   "max_version": "",
 *   "cipher_suites": [],
 *   "certificate": [],
 *   "certificate_path": "",
 *   "key": [],
 *   "key_path": "",
 *   "acme": {
 *   "domain": [],
 *   "data_directory": "",
 *   "default_server_name": "",
 *   "email": "",
 *   "provider": "",
 *   "disable_http_challenge": false,
 *   "disable_tls_alpn_challenge": false,
 *   "alternative_http_port": 0,
 *   "alternative_tls_port": 0,
 *   "external_account": {
 *     "key_id": "",
 *     "mac_key": ""
 *   },
 *   "dns01_challenge": {}
 *   },
 *   "ech": {
 *     "enabled": false,
 *     "pq_signature_schemes_enabled": false,
 *     "dynamic_record_sizing_disabled": false,
 *     "key": [],
 *     "key_path": ""
 *   },
 *   "reality": {
 *     "enabled": false,
 *     "handshake": {
 *       "server": "google.com",
 *       "server_port": 443,
 *     },
 *     "private_key": "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
 *     "short_id": ["0123456789abcdef"],
 *     "max_time_difference": "1m"
 *   }
 * }
 * ```
 *
 * @param key Enable TLS
 * @param server_name Used to verify the hostname on the returned certificates
 *   unless insecure is given. It is also included in the client's handshake to
 *   support virtual hosting unless it is an IP address.
 * @param key_path
 *
 * @param acme
 * @param ech
 */
case class InboundTLS(
  enabled: Boolean,
  server_name: Option[String] = None,
  /**
   * List of supported application level protocols, in order of preference.
   *
   * If both peers support ALPN, the selected protocol will be one from this
   * list, and the connection will fail if there is no mutually supported
   * protocol.
   *
   * See [Application-Layer Protocol
   * Negotiation](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).
   */
  alpn: Option[Seq[ALPN]] = None,
  /**
   * The minimum TLS version that is acceptable.
   *
   * By default, TLS 1.2 is currently used as the minimum when acting as a
   * client, and TLS 1.0 when acting as a server.
   */
  min_version: Option[TLSVersion] = None,
  /**
   * The maximum TLS version that is acceptable.
   *
   * By default, the maximum version is currently TLS 1.3.
   */
  max_version: Option[TLSVersion] = None,
  /**
   * A list of enabled TLS 1.0–1.2 cipher suites. The order of the list is
   * ignored. Note that TLS 1.3 cipher suites are not configurable.
   *
   * If empty, a safe default list is used. The default cipher suites might
   * change over time.
   */
  cipher_suites: Option[Seq[String]] = None,
  /** The server certificate line array, in PEM format. */
  certificate: Option[Seq[String]] = None,
  /**
   * > [!NOTE]
   *
   * > Will be automatically reloaded if file modified.
   *
   * The path to the server certificate, in PEM format.
   */
  certificate_path: Option[PathLike] = None,

  /** The server private key line array, in PEM format. */
  key: Option[Seq[String]] = None,
  /**
   * The path to the server certificate, in PEM format.
   *
   * > [!NOTE]
   *
   * > Will be automatically reloaded if file modified.
   */
  key_path: Option[PathLike] = None,
  /** See [[ACME]] */
  acme: Option[ACME] = None,
  /** See [[ECH]] */
  ech: Option[ECH] = None,
  /** See [[RealityTLS]] */
  reality: Option[Null] = None,
) extends BaseTLS

case class OutboundTLS(
  /** Enable TLS. */
  enabled: Boolean,
  /** Do not send server name in ClientHello. */
  disable_sni: Option[Boolean] = None,
  /**
   * Used to verify the hostname on the returned certificates unless insecure is
   * given.
   *
   * It is also included in the client's handshake to support virtual hosting
   * unless it is an IP address.
   */
  server_name: Option[String] = None,
  /** Accepts any server certificate. */
  insecure: Option[Boolean] = None,

  /**
   * List of supported application level protocols, in order of preference.
   *
   * If both peers support ALPN, the selected protocol will be one from this
   * list, and the connection will fail if there is no mutually supported
   * protocol.
   *
   * See [Application-Layer Protocol
   * Negotiation](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).
   */
  alpn: Option[Seq[ALPN]] = None,
  /**
   * The minimum TLS version that is acceptable.
   *
   * By default, TLS 1.2 is currently used as the minimum when acting as a
   * client, and TLS 1.0 when acting as a server.
   */
  min_version: Option[TLSVersion] = None,
  /**
   * The maximum TLS version that is acceptable.
   *
   * By default, the maximum version is currently TLS 1.3.
   */
  max_version: Option[TLSVersion] = None,
  /**
   * A list of enabled TLS 1.0–1.2 cipher suites. The order of the list is
   * ignored. Note that TLS 1.3 cipher suites are not configurable.
   *
   * If empty, a safe default list is used. The default cipher suites might
   * change over time.
   */
  cipher_suites: Option[Seq[String]] = None,
  /** The server certificate line array, in PEM format. */
  certificate: Option[Seq[String]] = None,
  /**
   * > [!NOTE]
   *
   * > Will be automatically reloaded if file modified.
   *
   * The path to the server certificate, in PEM format.
   */
  certificate_path: Option[PathLike] = None,

  /** See [[ECH]] */
  ech: Option[ECH] = None,
  /** See [[UTLS]] */
  utls: Option[UTLS] = None,
) extends BaseTLS
