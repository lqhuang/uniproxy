from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from attrs import frozen
from uniproxy.typing import ProtocolType

from .base import BaseProtocol


class ShadowsocksCipher(StrEnum):
    AEAD_AES_128_GCM = "aes-128-gcm"
    ADAD_AES_256_GCM = "aes-256-gcm"
    AEAD_CHACHA20_IETF_POLY1305 = "chacha20-ietf-poly1305"
    AEAD_2022_BLAKE3_AES_128_GCM = "2022-blake3-aes-128-gcm"
    AEAD_2022_BLAKE3_AES_256_GCM = "2022-blake3-aes-256-gcm"
    AEAD_2022_BLAKE3_CHACHA20_POLY1305 = "2022-blake3-chacha20-poly1305"
    AEAD_2022_BLAKE3_CHACHA8_POLY1305 = "2022-blake3-chacha8-poly1305"


LiteralShadowsocksCipher = Literal[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
]


class SSPlugin:
    command: str
    opts: dict[str, Any]


@frozen
class ShadowsocksProtocol(BaseProtocol):
    method: ShadowsocksCipher | LiteralShadowsocksCipher
    password: str
    udp: bool = True
    plugin: SSPlugin | None = None

    type: Literal[ProtocolType.SHADOWSOCKS] = ProtocolType.SHADOWSOCKS

    # surge_extra: None = None
    "test-udp=google.com@1.1.1.1"

    def as_clash(self) -> dict[str, Any]:
        """
        YAML example:

        ```yaml
        name: "proxy-name"
        type: "ss"
        server: host
        port: 8842
        cipher: "aes-256-gcm"
        password: "x-secret-token"
        udp: true
        ```
        """
        return {
            "name": self.name,
            "type": "ss",
            "server": self.host,
            "port": self.port,
            "cipher": self.method,
            "password": self.password,
            "udp": self.udp,
        }

    def as_surge(self) -> dict:
        """
        ini example:

        ```ini
        Proxy-SS = ss, 1.2.3.4, 8000, encrypt-method=chacha20-ietf-poly1305, password=abcd1234, udp-relay=true
        ```
        """
        return {
            self.name: (
                f"ss, {self.host}, {self.port}, "
                f"encrypt-method={self.method}, password={self.password}, "
                f"udp-relay={str(self.udp).lower()}, ecn=true"
            )
        }


class SSServer:
    method: ShadowsocksCipher | LiteralShadowsocksCipher
    password: str
    udp: bool = True
    plugin: SSPlugin | None = None
