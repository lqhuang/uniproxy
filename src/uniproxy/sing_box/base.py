from __future__ import annotations

from attrs import frozen


@frozen
class BaseOutbound:
    type: str
    tag: str

    def __str__(self) -> str:
        return str(self.tag)


@frozen
class BaseInbound:
    type: str
    tag: str

    def __str__(self) -> str:
        return str(self.tag)
