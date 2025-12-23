from __future__ import annotations

from typing import Literal

from attrs import frozen

from uniproxy.abc import AbstractSurge
from uniproxy.shared import TLS

from .typing import _ProtocolOptions


@frozen
class SurgeTLS(AbstractSurge):
    skip_cert_verify: bool | None = None
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
            "skip-cert-verify": str(self.skip_cert_verify).lower()
            if self.skip_cert_verify is not None
            else None,
            "sni": self.sni,
            "server-cert-fingerprint-sha256": self.server_cert_fingerprint_sha256,
        }
        return ", ".join(f"{k}={v}" for k, v in config.items() if v is not None)

    @classmethod
    def from_uniproxy(cls, tls: TLS | None) -> SurgeTLS:
        if tls is None:
            sni = None
        elif tls.sni is False:
            sni = "off"
        else:
            sni = tls.server_name

        return cls(
            skip_cert_verify=False if tls is None else tls.verify is False,
            sni=sni,
            # TODO: Implement this
            # server_cert_fingerprint_sha256=tls.server_cert_fingerprint_sha256,
        )
