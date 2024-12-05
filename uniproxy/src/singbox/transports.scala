package uniproxy.singbox.transports

import uniproxy.singbox.abc.AbstractSingBox
import uniproxy.singbox.typing.{DomainStrategy, TLSVersion, TransportType}
import uniproxy.singbox.shared.Fallback

enum Transport extends AbstractSingBox {
  case HTTP
  case HTTPS
}
