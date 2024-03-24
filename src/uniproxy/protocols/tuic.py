from __future__ import annotations

from typing import Literal

from attrs import frozen

from .base import BaseProtocol
from .std import TLS


@frozen
class TuicProtocol(BaseProtocol):
    token: str
    version: int
    tls: TLS
    disable_sni: bool = False
    udp_mode: Literal["naive", "quic"] = "quic"
    congestion_control: Literal["cubic", "new_reno", "bbr"] = "bbr"
    reduce_rtt: bool = False
    type: Literal["tuic"] = "tuic"
