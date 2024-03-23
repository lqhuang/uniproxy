from .base import BaseInbound
from .dns import DnsStrategy


class MixinListenFields:
    listen: str
    listen_port: int | None = None
    tcp_fast_open: bool | None = None
    tcp_multi_path: bool | None = None
    udp_fragment: bool | None = None

    # UDP NAT expiration time in seconds.
    #
    # `5m` is used by default.
    udp_timeout: str | None = None

    # If set, connections will be forwarded to the specified inbound.
    #
    # Requires target inbound support, see Injectable.
    detour: BaseInbound | str | None = None

    sniff: bool | None = None
    sniff_override_destination: bool | None = None
    sniff_timeout: str | None = None

    # One of `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    #
    # If set, the requested domain name will be resolved to IP before routing.
    #
    # If `sniff_override_destination` is in effect, its value will be taken as a fallback.
    domain_strategy: DnsStrategy | None = None

    udp_disable_domain_unmapping: bool | None = None
