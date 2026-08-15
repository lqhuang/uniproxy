from __future__ import annotations

from typing import Literal, Sequence

from attrs import define

from .base import AbstractSingBox, BaseService
from .http_clients import HttpClient
from .shared import InboundTLS, ListenableMixin, ListenFieldsMixin


@define
class Dashboard(AbstractSingBox):
    enabled: bool | None = None
    path: str | None = None
    download_url: str | None = None
    http_client: HttpClient | None = None
    update_interval: int | None = None
    """
    Update interval of the dashboard.

    `1d` will be used by default.
    """


@define(slots=False)
class _SingBoxApiMixin:
    secret: str | None = None
    access_control_allow_origin: Sequence[str] | None = None
    access_control_allow_private_network: bool | None = None
    dashboard: Dashboard | bool | None = None
    tls: InboundTLS | None = None


@define
class ApiService(ListenFieldsMixin, _SingBoxApiMixin, ListenableMixin, BaseService):
    """
    sing-box API

    > [!NEW]
    >
    > Since sing-box 1.14.0

    The sing-box API service is a gRPC server for observing and controlling the running sing-box instance.

    Structure:


    ```json
    {
        "type": "api",

        ... // Listen Fields

        "secret": "",
        "access_control_allow_origin": [],
        "access_control_allow_private_network": false,
        "dashboard": {
            "enabled": true,
            "path": "",
            "download_url": "",
            "http_client": "", // or {}
            "update_interval": ""
        },
        "tls": {}
    }
    ```

    Reference:

    - https://sing-box.sagernet.org/configuration/service/api/
    """

    type: Literal["api"] = "api"


type Service = ApiService
