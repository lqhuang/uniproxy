from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.abc import AbstractSurge

from .typing import _ProtocolOptions


@define
class SurgeTLS(AbstractSurge):
    skip_cert_verify: bool = False
    """
    If this option is enabled, Surge will not verify the server's certificate.

    Optional, "true" or "false" (Default: false).
    """

    sni: Literal["off"] | str | None = None
    """
    Customize the Server Name Indication (SNI) during the TLS handshake.
    Use `sni=off` to turn off SNI completely. By default, Surge sends the SNI
    using the `hostname` like most browsers.
    """

    server_cert_fingerprint_sha256: str | None = None
    """
    Use a pinned server certificate instead of the standard X.509 validation.
    """

    def __str__(self) -> str:
        config: _ProtocolOptions = {
            "skip-cert-verify": str(self.skip_cert_verify).lower(),
            "sni": self.sni,
            "server-cert-fingerprint-sha256": self.server_cert_fingerprint_sha256,
        }
        return ", ".join(f"{k}={v}" for k, v in config.items() if v is not None)
