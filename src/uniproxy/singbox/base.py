from __future__ import annotations

from typing import ClassVar, Literal

from attrs import define


class AbstractSingBox:
    """
    Abstract SingBox Class

    All sing-box classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "sing-box"


@define(slots=False)
class BaseOutbound(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return self.tag


@define(slots=False)
class BaseInbound(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return self.tag


@define(slots=False)
class BaseEndpoint(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return self.tag


@define(slots=False)
class BaseDnsServer(AbstractSingBox):
    tag: str
    # type: str

    def __str__(self) -> str:
        return self.tag


@define(slots=False)
class BaseRuleSet(AbstractSingBox):
    tag: str
    format: Literal["binary", "source"]
    # type: str

    def __str__(self) -> str:
        return self.tag


@define(slots=False)
class BaseService(AbstractSingBox):
    """
    since sing-box 1.12.0
    """

    tag: str

    def __str__(self) -> str:
        return self.tag
