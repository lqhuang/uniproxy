from __future__ import annotations

from typing import ClassVar, Literal, override

from abc import ABC
from functools import cached_property

from attrs import define

from uniproxy.abc import BaseTaggable


class AbstractSingBox(ABC):
    """
    Abstract SingBox Class

    All sing-box classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "sing-box"


@define(slots=False)
class BaseOutbound(BaseTaggable, AbstractSingBox):
    tag: str

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.tag


@define(slots=False)
class BaseInbound(BaseTaggable, AbstractSingBox):
    tag: str

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.tag


@define(slots=False)
class BaseEndpoint(BaseTaggable, AbstractSingBox):
    tag: str

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.tag


@define(slots=False)
class BaseDnsServer(BaseTaggable, AbstractSingBox):
    tag: str

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.tag


@define(slots=False)
class BaseDnsRule(AbstractSingBox): ...


@define(slots=False)
class BaseRule(AbstractSingBox): ...


@define(slots=False)
class BaseRuleSet(BaseTaggable, AbstractSingBox):
    tag: str

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.tag


@define(slots=False)
class BaseService(BaseTaggable, AbstractSingBox):
    """
    since sing-box 1.12.0
    """

    tag: str

    @cached_property
    @override
    def to_tag(self) -> str:
        return self.tag
