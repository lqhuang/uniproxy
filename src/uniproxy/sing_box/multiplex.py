from typing import Literal


class InboundMultiplex:
    enabled: bool | None = None
    padding: bool | None = None
    # brutal: dict | None = None


class OutboundMultiplex:
    """
    ```json
    {
        "enabled": true,
        "protocol": "smux",
        "max_connections": 4,
        "min_streams": 4,
        "max_streams": 0,
        "padding": false,
        "brutal": {},
    }
    ```
    """

    # Enable multiplex.
    enabled: bool | None = None
    # Multiplex protocol.
    #
    # | Protocol | Description                        |
    # | -------- | ---------------------------------- |
    # | smux     | https://github.com/xtaci/smux      |
    # | yamux    | https://github.com/hashicorp/yamux |
    # | h2mux    | https://golang.org/x/net/http2     |
    #
    # `h2mux` is used by default.
    protocol: Literal["smux", "yamux", "h2mux"] | None = None
    # Max connections. Conflict with `max_streams`.
    max_connections: int | None = None
    # Minimum multiplexed streams in a connection before opening a new connection.
    # Conflict with `max_streams`.
    min_streams: int | None = None
    # Maximum multiplexed streams in a connection before opening a new connection.
    # Conflict with `max_connections` and `min_streams`.
    max_streams: int | None = None
    # Enable padding for each stream.
    padding: bool | None = None
    # # See TCP Brutal for details.
    # brutal: dict | None = None
