from enum import StrEnum


class SniffProtocol(StrEnum):
    HTTP = "HTTP"
    TLS = "TLS"
    QUIC = "QUIC"
    STUN = "STUN"
    DNS = "DNS"
