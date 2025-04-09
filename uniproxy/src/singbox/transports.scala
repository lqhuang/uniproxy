package uniproxy.singbox.transports

import uniproxy.singbox.abc.AbstractSingBox
import uniproxy.singbox.typing.{DomainStrategy, Fallback, TLSVersion, TransportType}

enum Transport(`type`: String) extends AbstractSingBox {
  case HTTP() extends Transport("http")
  case WebSocket() extends Transport("ws")
  case QUIC() extends Transport("quic")
  case GRPC() extends Transport("grpc")
  case HTTPUpgrade() extends Transport("httpupgrade")
}
