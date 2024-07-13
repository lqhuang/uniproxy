from __future__ import annotations

from typing import Literal

from attrs import field, frozen

from .base import BaseInbound, BaseOutbound
from .dns import DNS
from .route import Route


@frozen
class SingBoxConfig:
    """
    `sing-box` uses JSON for configuration files.

    Ref: https://sing-box.sagernet.org/configuration/
    """

    dns: DNS
    inbounds: list[BaseInbound]
    outbounds: list[BaseOutbound]
    route: Route
    log: Log | None
    ntp: NTP | None
    experimental: dict = field(factory=dict)


class Log:
    """
    Ref: https://sing-box.sagernet.org/configuration/log/
    """

    # Disable logging, no output after start.
    disabled: bool
    # Log level.
    level: Literal["trace", "debug", "info", "warn", "error", "fatal", "panic"]
    # Output file path. Will not write log to console after enable.
    output: str
    # Add time to each line.
    timestamp: bool


class NTP:
    """
    Built-in NTP client service.

    If enabled, it will provide time for protocols like TLS/Shadowsocks/VMess,
    which is useful for environments where time synchronization is not possible.

    Ref: https://sing-box.sagernet.org/configuration/ntp/
    """

    ...
