from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from .inbounds import Inbound
from .outbounds import Outbound


class SingBoxConfig:
    """
    `sing-box` uses JSON for configuration files.

    Ref: https://sing-box.sagernet.org/configuration/
    """

    log: LogConfig
    dns: DnsConfig
    ntp: NtpConfig
    inbounds: list[Inbound]
    outbounds: list[Outbound]
    route: dict
    experimental: dict


class LogConfig:
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


class DnsConfig:
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/
    """

    servers: DnsServersSettings
    rules: DnsRulesSettings
    # Default dns server tag. The first server will be used if empty.
    final: str | None = None
    # Default domain strategy for resolving the domain names. Take no effect if `server.strategy` is set.
    strategy: Literal[
        "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"
    ] | None = None
    # Disable dns cache.
    disable_cache: bool = False
    # Disable dns cache expire.
    disable_expire: bool = False
    # Make each DNS server's cache independent for special purposes.
    # If enabled, will slightly degrade performance.
    independent_cache: bool = False
    # Stores a reverse mapping of IP addresses after responding to a DNS query
    # in order to provide domain names when routing.
    # Since this process relies on the act of resolving domain names by
    # an application before making a request, it can be problematic in
    # environments such as macOS, where DNS is proxied and cached by
    # the system.
    reverse_mapping: bool = False
    # FakeIP settings.
    fakeip: FakeIPSettings | None = None


class DnsServersSettings:
    ...


class DnsRulesSettings:
    ...


class FakeIPSettings:
    """
    Ref: https://sing-box.sagernet.org/configuration/dns/fakeip/
    """

    ...


class NtpConfig:
    """
    Built-in NTP client service.

    If enabled, it will provide time for protocols like TLS/Shadowsocks/VMess,
    which is useful for environments where time synchronization is not possible.

    Ref: https://sing-box.sagernet.org/configuration/ntp/
    """

    ...
