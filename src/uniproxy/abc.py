from __future__ import annotations

from typing import ClassVar


class AbstractUniproxy:
    __uniproxy_impl__: ClassVar[str] = "uniproxy"


class AbstractSingBox:
    __uniproxy_impl__: ClassVar[str] = "sing-box"


class AbstractSurge:
    __uniproxy_impl__: ClassVar[str] = "surge"

    @classmethod
    def from_uniproxy(cls, uniproxy: AbstractUniproxy) -> AbstractSurge:
        """
        Convert uniproxy instance to Clash object
        """
        ...

    def to_uniproxy(self) -> AbstractUniproxy:
        """
        Convert Clash object to uniproxy
        """
        ...


class AbstractClash:
    """
    Abstract Clash class

    All Clash classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "clash"

    @classmethod
    def from_uniproxy(cls, uniproxy: AbstractUniproxy) -> AbstractClash:
        """
        Convert uniproxy instance to Clash object
        """
        ...

    def to_uniproxy(self) -> AbstractUniproxy:
        """
        Convert Clash object to uniproxy
        """
        ...
