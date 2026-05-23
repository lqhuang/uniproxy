from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.abc import AbstractSingBox

from .shared import DialFieldsMixin, OutboundTLS


@define(slots=False)
class BaseHttpClient(AbstractSingBox):
    """
    > [!NOTE]
    > Since sing-box 1.14.0

    A string or an object.

    When string, the tag of a shared HTTP Client defined in top-level `http_clients`.

    When object:

    ```json
    {
      "engine": "",
      "version": 0,
      "disable_version_fallback": false,
      "headers": {},

      ... // HTTP2 Fields

      "tls": {},

      ... // Dial Fields
    }
    ```
    """

    tag: str

    engine: Literal["go", "apple"] | None = None
    """
    HTTP engine to use.

    Values:

    - `go` (default)
    - `apple`
    """

    disable_version_fallback: bool | None = None
    """
    Disable automatic fallback to lower HTTP version.
    """

    tls: OutboundTLS | None = None

    headers: dict[str, str] | None = None
    """Additional headers to add to each request."""


@define
class Http1Client(DialFieldsMixin, BaseHttpClient):
    version: Literal[1] = 1
    """HTTP version 1."""


@define(slots=False)
class Http2FieldsMixin:
    idle_timeout: str | None = None
    """
    Idle connection timeout, in golang's Duration format.
    """

    keep_alive_period: str | None = None
    """
    Keep alive period, in golang's Duration format.
    """

    stream_receive_window: str | None = None
    """
    HTTP2 stream-level flow-control receive window size.

    Accepts memory size format, e.g. "64 MB".
    """

    connection_receive_window: str | None = None
    """
    HTTP2 connection-level flow-control receive window size.

    Accepts memory size format, e.g. "64 MB".
    """

    max_concurrent_streams: int | None = None
    """The maximum number of concurrent streams the client can open."""


@define
class Http2Client(DialFieldsMixin, Http2FieldsMixin, BaseHttpClient):
    version: Literal[2] = 2


@define(slots=False)
class QuicFieldsMixin: ...


@define
class Http3Client(DialFieldsMixin, QuicFieldsMixin, BaseHttpClient):
    version: Literal[3] = 3


type HttpClient = Http1Client | Http2Client | Http3Client
