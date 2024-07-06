from __future__ import annotations


class AbstractUniproxy:
    __uniproxy_impl__ = "uniproxy"


class AbstractSurge:
    __uniproxy_impl__ = "surge"


class AbstractClash:
    """
    Abstract Clash class

    All Clash classes should inherit from this class.
    """

    __uniproxy_impl__ = "clash"


class AbstractSingBox:
    __uniproxy_impl__ = "sing-box"
