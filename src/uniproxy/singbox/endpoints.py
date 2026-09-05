"""
References:

- https://sing-box.sagernet.org/configuration/endpoint/
"""

from __future__ import annotations

from typing import Literal, Sequence
from uniproxy.typing import IPAddress, ServerAddress

from attrs import define

from .base import BaseEndpoint
from .shared import DialFieldsMixin


@define
class Peer:
    public_key: str
    """
    **Required**

    WireGuard peer public key.
    """

    allowed_ips: Sequence[IPAddress]
    """
    **Required**

    WireGuard allowed IPs.
    """

    pre_shared_key: str | None = None
    """WireGuard pre-shared key."""

    address: ServerAddress | None = None
    """
    WireGuard peer address.
    """

    port: int | None = None
    """
    WireGuard peer port.
    """

    persistent_keepalive_interval: int | None = None
    """
    WireGuard persistent keepalive interval, in seconds.

    Disabled by default.
    """

    reserved: Sequence[int] | None = None
    """
    WireGuard reserved field bytes.
    """


@define(slots=False)
class WireguardMixin:
    address: Sequence[IPAddress]
    """
    **Required**

    List of IP (v4 or v6) address prefixes to be assigned to the interface.
    """

    private_key: str
    """
    **Required**

    WireGuard requires base64-encoded public and private keys.
    These can be generated using the wg(8) utility:

    ```
    wg genkey
    echo "private key" || wg pubkey
    ```
    """

    peers: Sequence[Peer]
    """
    **Required**

    List of WireGuard peers.
    """

    reserved: Sequence[int] | None = None
    """
    WireGuard reserved field bytes.
    """

    system: str | None = None
    """
    Use system interface.

    Requires privilege and cannot conflict with exists system interfaces.
    """

    name: str | None = None
    """
    Custom interface name for system interface.
    """

    mtu: int | None = None
    """
    WireGuard MTU.

    `1408` will be used if empty.
    """

    udp_timeout: str | None = None
    """
    UDP NAT expiration time.

    `5m` will be used by default.
    """

    workers: int | None = None
    """
    WireGuard worker count. CPU count is used by default.
    """


@define
class WireguardEndpoint(DialFieldsMixin, WireguardMixin, BaseEndpoint):  # type: ignore[misc]
    """
    Examples:

    ```json
    {
      "type": "wireguard",
      "tag": "wg-ep",

      "system": false,
      "name": "",
      "mtu": 1408,
      "address": [],
      "private_key": "",
      "listen_port": 10000,
      "peers": [
        {
          "address": "127.0.0.1",
          "port": 10001,
          "public_key": "",
          "pre_shared_key": "",
          "allowed_ips": [],
          "persistent_keepalive_interval": 0,
          "reserved": [0, 0, 0]
        }
      ],
      "udp_timeout": "",
      "workers": 0,

      ... // Dial Fields
    }
    ```
    """

    type: Literal["wireguard"] = "wireguard"


@define(slots=False)
class OpenConnectToken:
    """One-time password token configuration."""

    mode: Literal["totp", "hotp", "stoken", "oidc"]
    secret: str | None = None
    secret_path: str | None = None
    pin: str | None = None
    password: str | None = None
    device_id: str | None = None
    counter: int | None = None

    def __attrs_post_init__(self) -> None:
        if self.secret is None and self.secret_path is None:
            raise ValueError(
                "One of `token.secret` or `token.secret_path` is required."
            )


@define(slots=False)
class OpenConnectMobile:
    """Mobile device metadata reported to the VPN server."""

    platform_version: str
    device_type: str
    device_unique_id: str


@define(slots=False)
class OpenConnectCSD:
    """Cisco Secure Desktop configuration."""

    wrapper_path: str | None = None


@define(slots=False)
class OpenConnectHIP:
    """Host Integrity Protection configuration."""

    wrapper_path: str | None = None


@define(slots=False)
class OpenConnectTNCCCertificate:
    """A certificate presented to the TNCC host checker."""

    certificate: Sequence[str] | None = None
    certificate_path: str | None = None


@define(slots=False)
class OpenConnectTNCC:
    """Trusted Network Connect Client configuration."""

    wrapper_path: str | None = None
    device_id: str | None = None
    user_agent: str | None = None
    machine_identification_enabled: bool | None = None
    certificates: Sequence[OpenConnectTNCCCertificate] | None = None


@define(slots=False)
class OpenConnectFortinetHostCheck:
    """Fortinet host-check configuration."""

    hostcheck: str | None = None
    check_virtual_desktop: str | None = None


@define(slots=False)
class OpenConnectTLS:
    """TLS configuration for the OpenConnect control connection."""

    insecure: bool | None = None
    server_name: str | None = None
    peer_fingerprint: Sequence[str] | None = None
    system_trust_disabled: bool | None = None
    certificate_authority: Sequence[str] | None = None
    certificate_authority_path: str | None = None
    client_certificate: Sequence[str] | None = None
    client_certificate_path: str | None = None
    client_key: Sequence[str] | None = None
    client_key_path: str | None = None
    client_key_password: str | None = None
    mca_certificate: Sequence[str] | None = None
    mca_certificate_path: str | None = None
    mca_key: Sequence[str] | None = None
    mca_key_path: str | None = None
    mca_key_password: str | None = None


@define(slots=False)
class OpenConnectFormEntry:
    """A pre-populated OpenConnect authentication form entry."""

    form_id: str | None = None
    submission_key: str | None = None
    name: str | None = None
    value: str | None = None
    promote: bool | None = None


@define(slots=False)
class OpenConnectEndpointMixin:
    server: str
    """OpenConnect server address or URL."""

    system: bool | None = None
    """Use a system interface instead of gVisor."""

    name: str | None = None
    """Custom name for the system interface."""

    udp_timeout: str | None = None
    """UDP NAT expiration time."""

    udp_mapping: (
        Literal[
            "endpoint_independent", "address_dependent", "address_and_port_dependent"
        ]
        | None
    ) = None
    """UDP NAT mapping behavior."""

    udp_filtering: (
        Literal[
            "endpoint_independent", "address_dependent", "address_and_port_dependent"
        ]
        | None
    ) = None
    """UDP NAT filtering behavior."""

    udp_nat_max: int | None = None
    """Maximum number of UDP NAT mappings."""

    flavor: Literal["anyconnect", "gp", "fortinet", "f5", "pulse", "nc"] | None = None
    username: str | None = None
    password: str | None = None
    auth_group: str | None = None
    cookie: str | None = None
    token: OpenConnectToken | None = None
    reported_os: str | None = None
    user_agent: str | None = None
    version: str | None = None
    local_hostname: str | None = None
    mobile: OpenConnectMobile | None = None
    csd: OpenConnectCSD | None = None
    hip: OpenConnectHIP | None = None
    tncc: OpenConnectTNCC | None = None
    fortinet_host_check: OpenConnectFortinetHostCheck | None = None
    no_udp: bool | None = None
    dtls_local_port: int | None = None
    compression_disabled: bool | None = None
    compression_mode: Literal["stateless", "all"] | None = None
    ipv6_disabled: bool | None = None
    http_keepalive_disabled: bool | None = None
    xml_post_disabled: bool | None = None
    external_auth_disabled: bool | None = None
    password_authentication_disabled: bool | None = None
    tcp_keep_alive_enabled: bool | None = None
    pfs: bool | None = None
    mtu: int | None = None
    base_mtu: int | None = None
    dpd_interval: str | None = None
    reconnect_timeout: str | None = None
    trojan_interval: str | None = None
    queue_length: int | None = None
    allow_insecure_crypto: bool | None = None
    tls: OpenConnectTLS | None = None
    form_entries: Sequence[OpenConnectFormEntry] | None = None
    on_demand: bool | None = None


@define()
class OpenConnectEndpoint(DialFieldsMixin, OpenConnectEndpointMixin, BaseEndpoint):
    """
    OpenConnect Client

    > [!NOTE]
    >
    > Since sing-box 1.14.0

    ```json
    {
        "type": "openconnect",
        "tag": "oc-client",

        "system": false,
        "name": "",

        ... // UDP NAT Fields

        "server": "vpn.example.com",
        "flavor": "anyconnect",
        "username": "",
        "password": "",
        "auth_group": "",
        "cookie": "",
        "token": {
            "mode": "",
            "secret": "",
            "secret_path": "",
            "pin": "",
            "password": "",
            "device_id": "",
            "counter": 0
        },
        "reported_os": "",
        "user_agent": "",
        "version": "",
        "local_hostname": "",
        "mobile": {
            "platform_version": "",
            "device_type": "",
            "device_unique_id": ""
        },
        "csd": {
            "wrapper_path": ""
        },
        "hip": {
            "wrapper_path": ""
        },
        "tncc": {
            "wrapper_path": "",
            "device_id": "",
            "user_agent": "",
            "machine_identification_enabled": false,
            "certificates": [
            {
                "certificate": [],
                "certificate_path": ""
            }
            ]
        },
        "fortinet_host_check": {
            "hostcheck": "",
            "check_virtual_desktop": ""
        },
        "no_udp": false,
        "dtls_local_port": 0,
        "compression_disabled": false,
        "compression_mode": "",
        "ipv6_disabled": false,
        "http_keepalive_disabled": false,
        "xml_post_disabled": false,
        "external_auth_disabled": false,
        "password_authentication_disabled": false,
        "tcp_keep_alive_enabled": false,
        "pfs": false,
        "mtu": 0,
        "base_mtu": 0,
        "dpd_interval": "",
        "reconnect_timeout": "",
        "trojan_interval": "",
        "queue_length": 0,
        "allow_insecure_crypto": false,
        "tls": {
            "insecure": false,
            "server_name": "",
            "peer_fingerprint": [],
            "system_trust_disabled": false,
            "certificate_authority": [],
            "certificate_authority_path": "",
            "client_certificate": [],
            "client_certificate_path": "",
            "client_key": [],
            "client_key_path": "",
            "client_key_password": "",
            "mca_certificate": [],
            "mca_certificate_path": "",
            "mca_key": [],
            "mca_key_path": "",
            "mca_key_password": ""
        },
        "form_entries": [
            {
            "form_id": "",
            "submission_key": "",
            "name": "",
            "value": "",
            "promote": false
            }
        ],
        "on_demand": false,

        ... // Dial Fields
    }
    ```
    """

    type: Literal["openconnect"] = "openconnect"


type Endpoint = WireguardEndpoint | OpenConnectEndpoint
