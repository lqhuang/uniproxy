from __future__ import annotations

from attrs import frozen

from uniproxy.singbox.typing import SingBoxNetwork

from .base import BaseInbound
from .shared import InboundTLS, MixinListenFields, User


@frozen
class DirectInbound(BaseInbound, MixinListenFields):
    # Listen network, one of `tcp`, `udp`.
    #
    # Both if empty.
    network: SingBoxNetwork | None = None

    # Override the connection destination address.
    override_address: str | None = None

    # Override the connection destination port.
    override_port: int | None = None


@frozen
class HTTPInbound(BaseInbound, MixinListenFields):
    users: list[User] | None = None
    tls: InboundTLS | None = None
    set_system_proxy: bool | None = None


@frozen
class Socks5Inbound(BaseInbound, MixinListenFields):
    users: list[User] | None = None
