import pytest

from uniproxy.uri import parse_ss_uri


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
