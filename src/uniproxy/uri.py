from __future__ import annotations

from typing import cast
from uniproxy.typing import ShadowsocksCipher

from urllib.parse import parse_qs, unquote_plus, urlparse

from uniproxy.utils import padded_b64decode


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
        padding = "=" * ((4 - len(result.username) % 4) % 4)
        encoded = result.username + padding
        method, password = padded_b64decode(encoded).decode().split(":", 1)
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
    )


def parse_trojan_uri(uri: str) -> dict:
    """Parse a Trojan URI.

    ```
    TROJAN-URI = trojan://password@remote_host:remote_port
    ```

    Example:

    ```
    trojan://98b34529-a3b9-448b-a371-0decd024ee0e@example.com:1780?allowInsecure=1&udp=1&peer=example.org&sni=example.com#Example+Trojan+Server
    ```

    References:

    1. [trojan-gfw/trojan-url](https://github.com/trojan-gfw/trojan-url)
    """
    result = urlparse(uri, allow_fragments=True)
    if result.scheme != "trojan":
        raise ValueError("Invalid URI scheme value '%s'" % result.scheme)
    if result.hostname is None:
        raise ValueError("Invalid hostname value '%s'" % result.hostname)

    if result.fragment is None:
        raise ValueError("Invalid fragment value '%s'" % result.fragment)

    if result.port is None:
        port = 443
    else:
        port = int(result.port)

    if result.password is None and result.username is not None:
        password = result.username
    else:
        raise ValueError("Invalid userinfo value '%s'" % result.netloc)

    if result.query:
        parsed = parse_qs(result.query)
        # Only support single value for each query parameter, and ignore unsupported parameters.
        count_perfield = [len(v) for v in parsed.values()]
        if any(count > 1 for count in count_perfield):
            raise ValueError("Invalid query parameter value '%s'" % result.query)
        query_params = {k: v[0] for k, v in parsed.items()}
    else:
        query_params = {}

    return dict(
        name=unquote_plus(result.fragment),
        server=result.hostname,
        port=port,
        password=password,
        # just flatten the query parameters into the result dict,
        # and let the caller decide which parameters to use.
        **query_params,
    )


def parse_anytls_uri(uri: str) -> dict:
    """Parse a AnyTLS URI.

    ref: https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md

    ```
    anytls://[auth@]hostname[:port]/?[key=value]&[key=value]...
    ```

    Example:

    ```
    anytls://letmein@example.com/?sni=real.example.com
    anytls://letmein@example.com/?sni=127.0.0.1&insecure=1
    anytls://0fdf77d7-d4ba-455e-9ed9-a98dd6d5489a@[2409:8a71:6a00:1953::615]:8964/?insecure=1
    ```
    """
    result = urlparse(uri, allow_fragments=True)
    if result.scheme != "anytls":
        raise ValueError("Invalid URI scheme value '%s'" % result.scheme)
    if result.hostname is None:
        raise ValueError("Invalid hostname value '%s'" % result.hostname)

    if result.fragment is None:
        raise ValueError("Invalid fragment value '%s'" % result.fragment)

    if result.port is None:
        port = 443
    else:
        port = int(result.port)

    if result.password is None and result.username is not None:
        password = result.username
    else:
        raise ValueError("Invalid userinfo value '%s'" % result.netloc)

    if result.query:
        parsed = parse_qs(result.query)
        # Only support single value for each query parameter, and ignore unsupported parameters.
        count_perfield = [len(v) for v in parsed.values()]
        if any(count > 1 for count in count_perfield):
            raise ValueError("Invalid query parameter value '%s'" % result.query)
        query_params = {k: v[0] for k, v in parsed.items()}
    else:
        query_params = {}

    sni = query_params.pop("sni", None)
    insecure = query_params.pop("insecure", None)
    if insecure is not None:
        if insecure == "1":
            insecure = True
        elif insecure == "0":
            insecure = False
        else:
            raise ValueError("Invalid value for 'insecure' parameter: '%s'" % insecure)

    sni_kw = {} if sni is None else {"sni": sni}
    insecure_kw = {} if insecure is None else {"insecure": insecure}

    return dict(
        name=unquote_plus(result.fragment),
        server=result.hostname,
        port=port,
        password=password,
        **sni_kw,
        **insecure_kw,
        # just flatten the query parameters into the result dict,
        # and let the caller decide which parameters to use.
        **query_params,
    )
