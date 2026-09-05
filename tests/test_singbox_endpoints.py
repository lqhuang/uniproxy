from __future__ import annotations

from xattrs import asdict
from xattrs.filters import exclude_if_none

from uniproxy.singbox.endpoints import (
    OpenConnectEndpoint,
    OpenConnectFormEntry,
    OpenConnectTLS,
    OpenConnectTNCC,
    OpenConnectTNCCCertificate,
    OpenConnectToken,
)


def test_openconnect_endpoint_serializes_documented_fields():
    endpoint = OpenConnectEndpoint(
        tag="openconnect-client",
        server="https://vpn.example.com",
        system=False,
        udp_timeout="1m",
        udp_mapping="address_dependent",
        udp_filtering="address_and_port_dependent",
        udp_nat_max=1024,
        flavor="anyconnect",
        token=OpenConnectToken(mode="totp", secret="secret", counter=1),
        tncc=OpenConnectTNCC(
            certificates=[OpenConnectTNCCCertificate(certificate=["certificate"])]
        ),
        tls=OpenConnectTLS(insecure=False, server_name="vpn.example.com"),
        form_entries=[OpenConnectFormEntry(name="username", value="alice")],
    )

    assert asdict(endpoint, filter=exclude_if_none) == {
        "tag": "openconnect-client",
        "server": "https://vpn.example.com",
        "system": False,
        "udp_timeout": "1m",
        "udp_mapping": "address_dependent",
        "udp_filtering": "address_and_port_dependent",
        "udp_nat_max": 1024,
        "flavor": "anyconnect",
        "token": {"mode": "totp", "secret": "secret", "counter": 1},
        "tncc": {"certificates": [{"certificate": ["certificate"]}]},
        "tls": {"insecure": False, "server_name": "vpn.example.com"},
        "form_entries": [{"name": "username", "value": "alice"}],
        "type": "openconnect",
    }
