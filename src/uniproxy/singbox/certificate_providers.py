from __future__ import annotations

from typing import Literal, Sequence

from attrs import define

from .base import AbstractSingBox
from .http_clients import HttpClient
from .shared import DNS01Challenge, ExternalAccount


@define(slots=False)
class BaseCertificateProvider(AbstractSingBox):
    tag: str


@define()
class AcmeCertificateProvider(BaseCertificateProvider):
    """
    ACME certificate provider.

    Structure:

    ```json
    {
        "type": "acme",
        "tag": "",

        "domain": [],
        "data_directory": "",
        "default_server_name": "",
        "email": "",
        "provider": "",
        "account_key": "",
        "disable_http_challenge": false,
        "disable_tls_alpn_challenge": false,
        "alternative_http_port": 0,
        "alternative_tls_port": 0,
        "external_account": {
            "key_id": "",
            "mac_key": ""
        },
        "dns01_challenge": {},
        "key_type": "",
        "profile": "",
        "http_client": "" // or {}
    }
    ```

    References:

    1. https://sing-box.sagernet.org/configuration/shared/certificate-provider/acme/
    """

    domain: Sequence[str]
    """List of domains."""

    data_directory: str | None = None
    """
    The directory used to store ACME data.

    `$XDG_DATA_HOME/certmagic|$HOME/.local/share/certmagic` is used if empty.
    """

    default_server_name: str | None = None
    """Server name used if the ClientHello ServerName is empty."""

    email: str | None = None
    """Email address for the ACME account."""

    provider: Literal["letsencrypt", "zerossl"] | str | None = None
    """
    The ACME CA provider to use.

    | Value                      | Provider       |
    |----------------------------|----------------|
    | `letsencrypt (default)`    | Let's Encrypt  |
    | `zerossl`                  | ZeroSSL        |
    | `https://...`              | Custom         |

    When `provider` is `zerossl`, sing-box will automatically request ZeroSSL EAB credentials if `email` is set and `external_account` is empty.

    When `provider` is zerossl, at least one of `external_account`, `email`, or `account_key` is required.
    """

    account_key: str | None = None
    """PEM-encoded private key of an existing ACME account."""

    disable_http_challenge: bool | None = None
    """Disable HTTP challenges."""

    disable_tls_alpn_challenge: bool | None = None
    """Disable TLS-ALPN challenges."""

    alternative_http_port: int | None = None
    """Alternate port for HTTP challenges."""

    alternative_tls_port: int | None = None
    """Alternate port for TLS-ALPN challenges."""

    external_account: ExternalAccount | None = None
    """External Account Binding credentials."""

    dns01_challenge: DNS01Challenge | None = None
    """DNS-01 challenge configuration."""

    key_type: Literal["ed25519", "p256", "p384", "rsa2048", "rsa4096"] | None = None
    """Private key type generated for new certificates."""

    profile: str | None = None
    """ACME certificate issuance profile."""

    http_client: HttpClient | str | None = None
    """HTTP client used for ACME provider requests."""

    type: Literal["acme"] = "acme"


type CertificateProvider = AcmeCertificateProvider
