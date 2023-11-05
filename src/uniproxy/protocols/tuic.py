from __future__ import annotations

from typing import Literal

from attrs import frozen
from uniproxy.typing import ProtocolType

from .base import BaseProtocol


@frozen
class TuicProtocol(BaseProtocol):
    password: str
    uuid: str
    version: int
    sni: str | None
    skip_cert_verify: bool
    alpn: list[str]
    udp: bool

    type: Literal[ProtocolType.TUIC] = ProtocolType.TUIC
