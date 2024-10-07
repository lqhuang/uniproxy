from __future__ import annotations

from typing import cast
from uniproxy.typing import ShadowsocksCipher

from base64 import b64decode
from urllib.parse import unquote_plus, urlparse


def parse_ss_uri(uri: str) -> dict:
    """Parse a Shadowsocks URI (SIP002).

    ```
    SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]

    userinfo = websafe-base64-encode-utf8(method  ":" password)
               method ":" password
    ```

    Example:

    ```
    ss://YmYtY2ZiOnRlc3Q@192.168.100.1:8888/?plugin=url-encoded-plugin-argument-value&unsupported-arguments=should-be-ignored#Dummy+profile+name
    ```

    Ref:

    - [SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html)
    """
    result = urlparse(uri, allow_fragments=True)
    if result.scheme != "ss":
        raise ValueError("Invalid URI scheme value '%s'" % result.scheme)
    if result.hostname is None:
        raise ValueError("Invalid hostname value '%s'" % result.hostname)
    if result.port is None:
        raise ValueError("Invalid port value '%s'" % result.port)
    if result.fragment is None:
        raise ValueError("Invalid fragment value '%s'" % result.fragment)

    if result.password is None and result.username is not None:
        method, password = b64decode(result.username).decode().split(":", 1)
    elif result.password is not None and result.username is not None:
        method, password = result.username, result.password
    else:
        raise ValueError("Invalid userinfo value '%s'" % result.netloc)

    if method not in {
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "2022-blake3-chacha8-poly1305",
    }:
        raise ValueError("Invalid method value '%s'" % method)

    return dict(
        name=unquote_plus(result.fragment),
        server=result.hostname,
        port=result.port,
        method=cast(ShadowsocksCipher, method),
        password=password,
        network="tcp_and_udp",
    )
