from __future__ import annotations

from typing import Literal
from uniproxy.typing import Backend

from uniproxy.clash.typing import RuleProviderFormatType
from uniproxy.singbox.typing import RuleSetSourceType

_ext_map: dict[str, str] = {
    "surge:conf": "conf",
    "sing-box:source": "json",
    "sing-box:binary": "srs",
    "mihomo:yaml": "yaml",
    "mihomo:text": "text",
    "mihomo:mrs": "mrs",
    "clash:yaml": "yaml",
    "clash:text": "text",
    "clash:mrs": "mrs",
}


def rule_set_extension(
    backend: Backend,
    format: Literal["conf"] | RuleProviderFormatType | RuleSetSourceType,
) -> str:
    return _ext_map[f"{backend}:{format}"]
