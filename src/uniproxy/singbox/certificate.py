from __future__ import annotations

from typing import Literal, Sequence

from xattrs import define

from .base import AbstractSingBox


@define()
class Certificate(AbstractSingBox):
    """
    Certificate

    Structure:

    ```json
    {
        "store": "",
        "certificate": [],
        "certificate_path": [],
        "certificate_directory_path": []
    }
    ```

    References:

    1. https://sing-box.sagernet.org/configuration/certificate
    """

    store: Literal["system", "mozilla", "chrome", "none"] | None = None
    certificate: Sequence[str] | None = None
    certificate_path: Sequence[str] | None = None
    certificate_directory_path: Sequence[str] | None = None
