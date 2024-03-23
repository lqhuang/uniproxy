from __future__ import annotations

from attrs import frozen

from uniproxy.common import User
from uniproxy.sing_box.constants import Network

from .base import BaseInbound
from .listen import MixinListenFields
from .tls import TLS


@frozen
class DirectInbound(BaseInbound, MixinListenFields):
    # Listen network, one of `tcp`, `udp`.
    #
    # Both if empty.
    network: Network | None = None

    # Override the connection destination address.
    override_address: str | None = None

    # Override the connection destination port.
    override_port: int | None = None


@frozen
class HTTPInbound(BaseInbound, MixinListenFields):
    users: list[User] | None = None
    tls: TLS | None = None
    set_system_proxy: bool | None = None


@frozen
class Socks5Inbound(BaseInbound, MixinListenFields):
    users: list[User] | None = None
