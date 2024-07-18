from __future__ import annotations

from attrs import define

from uniproxy.abc import AbstractSingBox

from .typing import InboundType, OutboundType


@define(slots=False)
class BaseOutbound(AbstractSingBox):
    tag: str
    type: OutboundType

    def __str__(self) -> str:
        return str(self.tag)


@define(slots=False)
class BaseInbound(AbstractSingBox):
    tag: str
    type: InboundType

    def __str__(self) -> str:
        return str(self.tag)
