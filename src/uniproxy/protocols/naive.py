from __future__ import annotations

from typing import Literal

from attrs import frozen

from uniproxy.typing import ProtocolType

from .base import BaseProtocol


@frozen
class NaiveProtocol(BaseProtocol):
    username: str
    password: str
    proto: Literal["http2", "quic"]
    extra_headers: dict[str, str] | None = None
    type: ProtocolType = "naive"
