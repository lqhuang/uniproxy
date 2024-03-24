from __future__ import annotations

from typing import Literal

from attrs import frozen


@frozen
class WGPeer:
    endpoint: str
    public_key: str
    allowed_ips: str | None
    keepalive: int | None
    preshared_key: str | None
    reserved_bits: list[int] | None


@frozen
class WireGuard:
    name: str
    host: str
    port: int
    private_key: str
    peers: list[WGPeer]
    dns: list
    mtu: int
    reserved_bits: list[int] | None
    type: Literal["wireguard"] = "wireguard"
