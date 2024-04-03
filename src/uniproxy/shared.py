from os import PathLike

from attrs import frozen


@frozen
class TLS:
    server_name: str | None = None
    enable_sni: bool | None = None
    alpn: list[str] | None = None
    verify: bool = True
    cert_ca: str | PathLike | None = None
    cert_private_key: str | PathLike | None = None
    cert_private_password: str | None = None
