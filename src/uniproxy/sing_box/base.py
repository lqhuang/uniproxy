from __future__ import annotations

from abc import ABC

from attrs import frozen

from .typing import InboundType, OutboundType


@frozen
class User:
    username: str
    password: str


class AbstractSingBox(ABC):
    __uniproxy_impl__ = "sing-box"


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
