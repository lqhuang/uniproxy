from __future__ import annotations

from typing import ClassVar


class AbstractUniproxy:
    """
    Abstract Uniproxy Class

    All uniproxy classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "uniproxy"


class AbstractSingBox:
    """
    Abstract SingBox Class

    All sing-box classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "sing-box"


class AbstractSurge:
    """
    Abstract Clash class

    All Surge classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "surge"


class AbstractClash:
    """
    Abstract Clash class

    All Clash classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "clash"
