from __future__ import annotations

from attrs import frozen


@frozen
class User:
    username: str
    password: str
