from __future__ import annotations

from xattrs import asdict
from xattrs.filters import exclude_if_none

from uniproxy.singbox.certificate_providers import AcmeCertificateProvider
from uniproxy.singbox.general import SingBoxConfig
from uniproxy.singbox.inbounds import HTTPInbound
from uniproxy.singbox.shared.tls import CloudflareDNS01Challenge


def test_acme_provider_serializes_documented_fields():
    provider = AcmeCertificateProvider(
        tag="acme",
        domain=["example.com"],
        email="admin@example.com",
        provider="letsencrypt",
        key_type="ed25519",
        dns01_challenge=CloudflareDNS01Challenge(
            api_token="token", zone_token="zone-token", propagation_timeout="2m"
        ),
    )

    assert asdict(provider, filter=exclude_if_none) == {
        "tag": "acme",
        "domain": ["example.com"],
        "email": "admin@example.com",
        "provider": "letsencrypt",
        "dns01_challenge": {
            "propagation_timeout": "2m",
            "api_token": "token",
            "zone_token": "zone-token",
            "provider": "cloudflare",
        },
        "key_type": "ed25519",
        "type": "acme",
    }


def test_singbox_config_accepts_certificate_providers():
    provider = AcmeCertificateProvider(tag="acme", domain=["example.com"])
    config = SingBoxConfig(
        inbounds=[HTTPInbound(tag="http", listen="127.0.0.1", listen_port=8080)],
        certificate_providers=[provider],
    )

    assert config.certificate_providers == [provider]
