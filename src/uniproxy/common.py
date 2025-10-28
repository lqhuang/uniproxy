from __future__ import annotations

from attrs import frozen


@frozen
class SimpleUser:
    """
    Simple User

    Used for protocols like Shadowsocks, Vmess, Trojan, etc.
    """

    name: str
    password: str


@frozen
class ProxyUser:
    """
    A generic proxy user with username and password.

    Used for protocols like HTTP, SOCKS5, etc.
    """

    username: str
    password: str


@frozen
class TuicUser:
    uuid: str
    """TUIC user uuid"""
    name: str | None = None
    """TUIC user name"""
    password: str | None = None
    """TUIC user password"""
