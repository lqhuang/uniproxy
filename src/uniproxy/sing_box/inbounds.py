from .base import Inbound


class HTTPInbound(Inbound):
    listen: str
    port: int
    settings: HTTPSettings


class Socks5Inbound(Inbound):
    listen: str
    port: int
    settings: Socks5Settings


class MixedInbound(Inbound):
    listen: str
    port: int
    settings: MixedSettings
