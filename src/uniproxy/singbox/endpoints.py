"""
References:

- https://sing-box.sagernet.org/configuration/endpoint/
"""

from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import IPAddress, ServerAddress

from attrs import define

from .base import BaseEndpoint
from .shared import DialFieldsMixin


@define
class Peer:
    public_key: str
    """
    **Required**

    WireGuard peer public key.
    """

    allowed_ips: Sequence[IPAddress]
    """
    **Required**

    WireGuard allowed IPs.
    """

    pre_shared_key: str | None = None
    """WireGuard pre-shared key."""

    address: ServerAddress | None = None
    """
    WireGuard peer address.
    """

    port: int | None = None
    """
    WireGuard peer port.
    """

    persistent_keepalive_interval: int | None = None
    """
    WireGuard persistent keepalive interval, in seconds.

    Disabled by default.
    """

    reserved: Sequence[int] | None = None
    """
    WireGuard reserved field bytes.
    """


@define(slots=False)
class WireguardMixin:
    address: Sequence[IPAddress]
    """
    **Required**

    List of IP (v4 or v6) address prefixes to be assigned to the interface.
    """

    private_key: str
    """
    **Required**

    WireGuard requires base64-encoded public and private keys.
    These can be generated using the wg(8) utility:

    ```
    wg genkey
    echo "private key" || wg pubkey
    ```
    """

    peers: Sequence[Peer]
    """
    **Required**

    List of WireGuard peers.
    """

    reserved: Sequence[int] | None = None
    """
    WireGuard reserved field bytes.
    """

    system: str | None = None
    """
    Use system interface.

    Requires privilege and cannot conflict with exists system interfaces.
    """

    name: str | None = None
    """
    Custom interface name for system interface.
    """

    mtu: int | None = None
    """
    WireGuard MTU.

    `1408` will be used if empty.
    """

    udp_timeout: str | None = None
    """
    UDP NAT expiration time.

    `5m` will be used by default.
    """

    workers: int | None = None
    """
    WireGuard worker count. CPU count is used by default.
    """


@define
class WireguardEndpoint(DialFieldsMixin, WireguardMixin, BaseEndpoint):  # type: ignore[misc]
    """
    Examples:

    ```json
    {
      "type": "wireguard",
      "tag": "wg-ep",

      "system": false,
      "name": "",
      "mtu": 1408,
      "address": [],
      "private_key": "",
      "listen_port": 10000,
      "peers": [
        {
          "address": "127.0.0.1",
          "port": 10001,
          "public_key": "",
          "pre_shared_key": "",
          "allowed_ips": [],
          "persistent_keepalive_interval": 0,
          "reserved": [0, 0, 0]
        }
      ],
      "udp_timeout": "",
      "workers": 0,

      ... // Dial Fields
    }
    ```
    """

    type: Literal["wireguard"] = "wireguard"
