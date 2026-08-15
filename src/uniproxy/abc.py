from __future__ import annotations

from typing import ClassVar


class AbstractUniproxy:
    """
    Abstract Uniproxy Class

    All uniproxy classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "uniproxy"

