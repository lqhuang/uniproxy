from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from abc import abstractmethod

from attrs import define

from uniproxy.abc import AbstractSingBox

from .typing import InboundType, OutboundType, RuleSetType

if TYPE_CHECKING:
    from .outbounds import SingBoxOutbound


@define(slots=False)
class BaseOutbound(AbstractSingBox):
    tag: str
    # type: OutboundType

    def __str__(self) -> str:
        return str(self.tag)

    @classmethod
    @abstractmethod
    def from_uniproxy(cls, protocol, **kwargs) -> SingBoxOutbound:
        raise NotImplementedError


@define(slots=False)
class BaseInbound(AbstractSingBox):
    tag: str
    listen: str | None
    listen_port: int | None
    # type: InboundType

    def __str__(self) -> str:
        return str(self.tag)


@define(slots=False)
class BaseDnsServer(AbstractSingBox):
    tag: str

    def __str__(self) -> str:
        return str(self.tag)


@define(slots=False)
class BaseRuleSet(AbstractSingBox):
    tag: str
    format: Literal["binary", "source"]
    # type: RuleSetType

    def __str__(self) -> str:
        return str(self.tag)
