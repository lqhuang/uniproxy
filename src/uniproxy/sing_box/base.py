from __future__ import annotations

from attrs import define, frozen

from uniproxy.abc import AbstractSingBox

from .typing import InboundType, OutboundType


@frozen
class User:
    username: str
    password: str


@define
class BaseOutbound(AbstractSingBox):
    tag: str
    type: OutboundType

    def __str__(self) -> str:
        return str(self.tag)


class BaseInbound(AbstractSingBox):
    tag: str
    type: InboundType

    def __str__(self) -> str:
        return str(self.tag)
