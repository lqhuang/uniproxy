from __future__ import annotations

from typing import Literal

from abc import abstractmethod

from attrs import define

from uniproxy.abc import AbstractSingBox


@define(slots=False)
class BaseOutbound(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return str(self.tag)

    @classmethod
    @abstractmethod
    def from_uniproxy(cls, protocol, **kwargs) -> BaseOutbound:
        raise NotImplementedError


@define(slots=False)
class BaseInbound(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return str(self.tag)


@define(slots=False)
class BaseEndpoint(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return str(self.tag)


@define(slots=False)
class BaseDnsServer(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return str(self.tag)


@define(slots=False)
class BaseRuleSet(AbstractSingBox):
    tag: str
    format: Literal["binary", "source"]
    # type: str

    def __str__(self) -> str:
        return str(self.tag)


@define(slots=False)
class BaseService(AbstractSingBox):
    """
    since sing-box 1.12.0
    """

    tag: str

    def __str__(self) -> str:
        return str(self.tag)
