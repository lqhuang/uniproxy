from __future__ import annotations

from typing import Sequence

from attrs import define

from uniproxy.abc import AbstractSingBox

from .base import BaseInbound, BaseOutbound
from .dns import DNS
from .route import Route
from .typing import LogLevel


@define
class SingBoxConfig(AbstractSingBox):
    """
    `sing-box` uses JSON for configuration files.

    Ref: https://sing-box.sagernet.org/configuration/
    """

    dns: DNS
    inbounds: Sequence[BaseInbound]
    outbounds: Sequence[BaseOutbound]
    route: Route
    log: Log | None = None
    ntp: NTP | None = None
    experimental: dict | None = None


@define
class Log(AbstractSingBox):
    """
    Ref: https://sing-box.sagernet.org/configuration/log/
    """

    disabled: bool | None = None
    """Disable logging, no output after start."""
    level: LogLevel | None = None
    """Log level."""
    output: str | None = None
    """Output file path. Will not write log to console after enable."""
    timestamp: bool | None = None
    """Add time to each line."""


class NTP(AbstractSingBox):
    """
    Built-in NTP client service.

    If enabled, it will provide time for protocols like TLS/Shadowsocks/VMess,
    which is useful for environments where time synchronization is not possible.

    Ref: https://sing-box.sagernet.org/configuration/ntp/
    """

    ...


@define
class Experimental(AbstractSingBox):
    """
    Ref: https://sing-box.sagernet.org/configuration/experimental/
    """

    cache_file: CacheFile | None = None
    clash_api: dict | None = None
    v2ray_api: dict | None = None


@define
class CacheFile(AbstractSingBox):
    """
        Ref: https://sing-box.sagernet.org/configuration/experimental/cache-file/

    ```json
    {
      "enabled": true,
      "path": "",
      "cache_id": "",
      "store_fakeip": false,
      "store_rdrc": false,
      "rdrc_timeout": ""
    }
    ```
    """
