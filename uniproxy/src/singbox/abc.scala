package uniproxy
package singbox
package abc

import com.comcast.ip4s.{Host, Port}
import upickle.default.ReadWriter

import uniproxy.singbox.typing.{InboundType, OutboundType, RuleSetFormat, RuleSetType}

/**
 * Abstract SingBox Class
 *
 * All sing-box classes should inherit from this class.
 */
abstract class AbstractSingBox

trait Inbound extends AbstractSingBox {
  val tag: String
  val `type`: InboundType
  override def toString: String = tag
}

trait Outbound extends AbstractSingBox {
  val tag: String
  val `type`: OutboundType
  override def toString: String = tag
}

trait Endpoint extends AbstractSingBox {
  val tag: String
  // val `type`: EndpointType
  override def toString: String = tag
}

abstract class AbstractRuleSet extends AbstractSingBox:
  val tag: String
  val format: RuleSetFormat

type InboundLike = Inbound | String
type OutboundLike = Outbound | String
type EndpointLike = Endpoint | String
type RuleSetLike = AbstractRuleSet | String

// object AbstractSingBox {

//   /** A common ReadWriter for Inbound and Outbound types. */
//   implicit val inboundOutboundRW: ReadWriter[InboundLike | OutboundLike] =
//     join(Inbound, OutboundLike.outboundRW)
// }
