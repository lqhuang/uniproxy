from __future__ import annotations

from typing import Sequence

from attrs import define

from .base import AbstractSingBox
from .dns import DNS
from .http_clients import HttpClient
from .inbounds import Inbound
from .outbounds import Outbound
from .route import Route
from .services import Service
from .typing import LogLevel


@define
class SingBoxConfig(AbstractSingBox):
    """
    `sing-box` uses JSON for configuration files.

    Ref: https://sing-box.sagernet.org/configuration/
    """

    dns: DNS
    inbounds: Sequence[Inbound]
    outbounds: Sequence[Outbound]
    route: Route
    http_clients: Sequence[HttpClient] | None = None
    certificate: None = None
    certificate_providers: None = None
    endpoints: None = None
    services: Sequence[Service] | None = None
    log: Log | None = None
    ntp: NTP | None = None
    # pyrefly: ignore [implicit-any-type-argument]
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
    # pyrefly: ignore [implicit-any-type-argument]
    clash_api: dict | None = None
    # pyrefly: ignore [implicit-any-type-argument]
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
