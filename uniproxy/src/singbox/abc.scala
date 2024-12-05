package uniproxy
package singbox
package abc

import com.comcast.ip4s.{Host, Port}

import uniproxy.singbox.typing.{InboundType, OutboundType, RuleSetFormat, RuleSetType}

/**
 * Abstract SingBox Class
 *
 * All sing-box classes should inherit from this class.
 */
abstract trait AbstractSingBox

abstract class AbstractOutbound extends AbstractSingBox:
  val tag: String

abstract class AbstractInbound extends AbstractSingBox:
  val tag: String

abstract class AbstractRuleSet extends AbstractSingBox:
  val tag: String
  val format: RuleSetFormat

type InboundLike = AbstractInbound | String
type OutboundLike = AbstractOutbound | String
type RuleSetLike = AbstractRuleSet | String
