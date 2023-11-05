from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from uniproxy.protocols.shadowsocks import LiteralShadowsocksCipher, ShadowsocksCipher

from .base import Outbound
from .shared import OutboundMultiplex


class ShadowsocksOutbound(Outbound):
    """

    Examples:

    ```json
    {
        "type": "shadowsocks",
        "tag": "ss-out",

        "server": "127.0.0.1",
        "server_port": 1080,
        "method": "2022-blake3-aes-128-gcm",
        "password": "8JCsPssfgS8tiRwiMlhARg==",
        "plugin": "",
        "plugin_opts": "",
        "network": "udp",
        "udp_over_tcp": false | {},
        "multiplex": {},

        ... // Dial Fields
    }
    ```
    """

    # The server address.
    server: IPv4Address | IPv6Address | str
    # The server port.
    server_port: int
    # Encryption methods.
    method: ShadowsocksCipher | LiteralShadowsocksCipher
    password: str
    # Shadowsocks SIP003 plugin, implemented in internal.
    plugin: Literal["obfs-local", "v2ray-plugin"] | None = None
    # Shadowsocks SIP003 plugin options.
    plugin_opts: str | None = None
    # Enabled network. One of `tcp`, `udp`.
    # Both is enabled by default.
    network: Literal["tcp", "udp"] | None = None
    # UDP over TCP configuration. Conflict with `multiplex`.
    udp_over_tcp: bool | dict = False
    # See Multiplex for details.
    multiplex: OutboundMultiplex | None = None
