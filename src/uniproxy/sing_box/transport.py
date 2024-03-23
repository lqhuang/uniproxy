from __future__ import annotations

from enum import StrEnum

from attrs import frozen


class TransportType(StrEnum):
    HTTP = "http"
    WS = "ws"
    QUIC = "quic"
    GRPC = "grpc"
    HTTP_UPGRADE = "httpupgrade"


@frozen
class BaseTransport:
    type: TransportType
