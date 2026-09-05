from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import AlpnType, ServerAddress

from pathlib import Path

from xattrs import define, field

from uniproxy.uniproxy.shared import TLS as UniproxyTLS
from uniproxy.utils import maybe_to_str, maybe_to_tag

from ..base import AbstractSingBox
from ..typing import TLSVersion


@define
class UTLS(AbstractSingBox):
    enabled: bool | None = None
    fingerprint: str | None = None


@define(slots=False)
class BaseDNS01Challenge(AbstractSingBox): ...


@define(slots=False)
class _ChallengeMixin:
    ttl: str | None = None
    """TTL for the temporary TXT record."""

    propagation_delay: str | None = None
    """Delay before propagation checks begin."""

    propagation_timeout: str | None = None
    """Maximum time to wait for DNS record propagation."""

    resolvers: Sequence[str] | None = None
    """Preferred DNS resolvers for propagation checks."""

    override_domain: str | None = None
    """Override the domain used to create the DNS challenge record."""


@define(slots=False)
class _AliMixin:
    access_key_id: str
    access_key_secret: str
    region_id: str
    security_token: str


@define
class AliDNS01Challenge(_ChallengeMixin, _AliMixin, BaseDNS01Challenge):
    provider: Literal["alidns"] = "alidns"


@define(slots=False)
class _CloudflareMixin:
    api_token: str
    zone_token: str


@define
class CloudflareDNS01Challenge(_ChallengeMixin, _CloudflareMixin, BaseDNS01Challenge):
    provider: Literal["cloudflare"] = "cloudflare"


@define(slots=False)
class _AcmeDnsMixin:
    username: str
    password: str
    subdomain: str
    server_url: str


@define
class AcmeDnsDNS01Challenge(_ChallengeMixin, _AcmeDnsMixin, BaseDNS01Challenge):
    provider: Literal["acmedns"] = "acmedns"


type DNS01Challenge = (
    AliDNS01Challenge | CloudflareDNS01Challenge | AcmeDnsDNS01Challenge
)


@define
class Fallback(AbstractSingBox):
    server: ServerAddress
    server_port: int


@define
class ECH(AbstractSingBox):
    enabled: bool | None = None
    pq_signature_schemes_enabled: bool | None = None
    dynamic_record_sizing_disabled: bool | None = None
    key: Sequence[str] | None = None
    key_path: str | None = None


@define
class ExternalAccount(AbstractSingBox):
    key_id: str | None = None
    """The key identifier."""
    mac_key: str | None = None
    """The MAC key."""


@define(slots=False)
class BaseTLS(AbstractSingBox):
    enabled: bool
    """Enable TLS."""

    server_name: str | None = None
    """
    Used to verify the hostname on the returned certificates unless insecure is given.

    It is also included in the client's handshake to support virtual hosting unless it is an IP address.
    """

    alpn: Sequence[AlpnType] | None = None
    """
    List of supported application level protocols, in order of preference.

    If both peers support ALPN, the selected protocol will be one from this list,
    and the connection will fail if there is no mutually supported protocol.

    See [Application-Layer Protocol Negotiation](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).
    """

    min_version: TLSVersion | None = None
    """
    The minimum TLS version that is acceptable.

    By default, TLS 1.2 is currently used as the minimum when acting as a
    client, and TLS 1.0 when acting as a server.
    """

    max_version: TLSVersion | None = None
    """
    The maximum TLS version that is acceptable.

    By default, the maximum version is currently TLS 1.3.
    """

    cipher_suites: Sequence[str] | None = None
    """
    A list of enabled TLS 1.0–1.2 cipher suites. The order of the list is
    ignored. Note that TLS 1.3 cipher suites are not configurable.

    If empty, a safe default list is used. The default cipher suites might change over time.
    """

    #
    # shared certificate settings
    #

    certificate: Sequence[str] | None = None
    """The server certificate line array, in PEM format."""

    certificate_path: Path | str | None = field(default=None, converter=maybe_to_str)
    """
    > [!NOTE]
    >
    >  Will be automatically reloaded if file modified.

    The path to the server certificate, in PEM format.
    """

    client_certificate: Sequence[str] | None = None
    """
    > [!NOTE]
    >
    > Since sing-box 1.13.0

    Client certificate chain line array, in PEM format.
    """

    client_certificate_path: Path | str | None = field(
        default=None, converter=maybe_to_tag
    )
    """
    > [!NOTE]
    >
    > Since sing-box 1.13.0

    The path to client certificate chain, in PEM format.
    """


@define
class InboundTLS(BaseTLS):
    """
    Known as Server TLS in sing-box config.
    """

    key: Sequence[str] | None = None
    """The server private key line array, in PEM format."""

    key_path: Path | str | None = field(default=None, converter=maybe_to_str)
    """
    > [!NOTE]
    >
    >  Will be automatically reloaded if file modified.

    The path to the server certificate, in PEM format.
    """

    # pyrefly: ignore [implicit-any-type-argument]
    client_authentication: dict | None = None
    """
    > [!NOTE]
    >
    > Since sing-box 1.13.0

    The type of client authentication to use.

    Available values:

    - `no` (default)
    - `request`
    - `require-any`
    - `verify-if-given`
    - `require-and-verify`

    One of `client_certificate`, `client_certificate_path`, or `client_certificate_public_key_sha256`
    is required if this option is set to `verify-if-given`, or `require-and-verify`.
    """

    client_certificate_public_key_sha256: Sequence[str] | None = None
    """
    > [!NOTE]
    >
    > Since sing-box 1.13.0

    List of SHA-256 hashes of client certificate public keys, in base64 format.
    """

    def __attrs_post_init__(self):
        if self.client_authentication in (
            "verify-if-given",
            "require-and-verify",
        ) and not any([
            self.client_certificate,
            self.client_certificate_path,
            self.client_certificate_public_key_sha256,
        ]):
            raise ValueError(
                "One of `client_certificate`, `client_certificate_path`, "
                "or `client_certificate_public_key_sha256` is required when "
                "`client_authentication` is set to "
                "`verify-if-given` or `require-and-verify`."
            )


@define
class OutboundTLS(BaseTLS):
    """
    Known as Client TLS in sing-box config.
    """

    engine: Literal["go", "apple", "windows"] | None = None
    """
    > [!NOTE]
    > Since sing-box 1.14.0

    TLS engine to use.

    Values:

    - `go` (default)
    - `apple`
    - `windows`
    """

    disable_sni: bool | None = None
    """Do not send server name in ClientHello."""

    insecure: bool | None = None
    """Accepts any server certificate."""

    certificate_public_key_sha256: Sequence[str] | None = None
    """
    > [!NOTE]
    >
    > Since sing-box 1.13.0

    List of SHA-256 hashes of server certificate public keys, in base64 format.
    """

    client_key: Sequence[str] | None = None
    """
    > [!NOTE]
    >
    > Since sing-box 1.13.0

    Client private key line array, in PEM format.
    """

    client_key_path: Path | str | None = field(default=None, converter=maybe_to_str)
    """
    > [!NOTE]
    >
    > Since sing-box 1.13.0

    The path to client private key, in PEM format.
    """

    ech: ECH | None = None

    @classmethod
    # pyrefly: ignore [implicit-any-parameter]
    def from_uniproxy(cls, tls: UniproxyTLS, **kwargs) -> OutboundTLS:
        # TODO: cert or cert path are not handled yet
        return cls(
            enabled=tls is not None,
            server_name=tls.server_name,
            insecure=not tls.verify,
            alpn=tls.alpn,
        )
