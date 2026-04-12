from __future__ import annotations

import pytest

from uniproxy.uri import parse_anytls_uri, parse_ss_uri, parse_trojan_uri


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (
            "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1",
            {
                "name": "Example1",
                "server": "192.168.100.1",
                "port": 8888,
                "method": "aes-128-gcm",
                "password": "test",
            },
        )
    ],
)
def test_parse_ss_uri(uri, expected):
    assert parse_ss_uri(uri) == expected


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (
            "trojan://password1234@google.com:8888/?sni=microsoft.com&udp=1#Example1",
            {
                "name": "Example1",
                "server": "google.com",
                "port": 8888,
                "password": "password1234",
                "sni": "microsoft.com",
                "udp": "1",
            },
        ),
        (
            r"trojan://password1234@google.com/?sni=microsoft.com&allowInsecure=1#NLD%20%E8%8D%B7%E5%85%B0",
            {
                "name": "NLD 荷兰",
                "server": "google.com",
                "port": 443,
                "password": "password1234",
                "sni": "microsoft.com",
                "allowInsecure": "1",
            },
        ),
    ],
)
def test_parse_trojan_uri(uri, expected):
    assert parse_trojan_uri(uri) == expected


def test_parse_trojan_uri_no_duplicate_params():
    # multiple same keys in parameters are not allowed
    url = (
        "trojan://password1234@google.com:8888/?sni=microsoft.com&udp=1&udp=0#Example1"
    )
    with pytest.raises(ValueError):
        parse_trojan_uri(url)


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (
            "anytls://letmein@example.com/?sni=real.example.com#Example1",
            {
                "name": "Example1",
                "server": "example.com",
                "port": 443,
                "password": "letmein",
                "sni": "real.example.com",
            },
        ),
        (
            "anytls://letmein@example.com/?sni=127.0.0.1&insecure=1#Example2",
            {
                "name": "Example2",
                "server": "example.com",
                "port": 443,
                "password": "letmein",
                "sni": "127.0.0.1",
                "insecure": True,
            },
        ),
        (
            "anytls://0fdf77d7-d4ba-455e-9ed9-a98dd6d5489a@[2409:8a71:6a00:1953::615]:8964/?insecure=1#Example3",
            {
                "name": "Example3",
                "server": "2409:8a71:6a00:1953::615",
                "port": 8964,
                "password": "0fdf77d7-d4ba-455e-9ed9-a98dd6d5489a",
                "insecure": True,
            },
        ),
    ],
)
def test_parse_anytls_uri(uri, expected):
    assert parse_anytls_uri(uri) == expected
