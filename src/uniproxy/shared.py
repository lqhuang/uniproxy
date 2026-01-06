from __future__ import annotations

from typing import Sequence
from uniproxy.typing import AlpnType

from os import PathLike

from attrs import define, frozen


@frozen
class TLS:
    server_name: str | None = None
    sni: bool | None = None
    # https://github.com/quicwg/base-drafts/wiki/ALPN-IDs-used-with-QUIC
    alpn: Sequence[AlpnType] | None = None
    verify: bool = True
    cert_ca: Sequence[str] | PathLike | None = None
    cert_private_key: Sequence[str] | PathLike | None = None
    cert_private_password: str | None = None


@frozen
class HealthCheck:
    enable: bool = True
    interval: float = 60
    lazy: bool = False
    url: str = "https://www.gstatic.com/generate_204"
    udp_url: str | None = "https://www.gstatic.com/generate_204"


@define(slots=False)
class NoResoleMixin:
    no_resolve: bool | None = None
