from __future__ import annotations

from typing import Literal, Sequence

from attrs import define, field

from uniproxy.uniproxy.base import BaseRule as UniproxyBaseRule
from uniproxy.uniproxy.rules import FinalRule as UniproxyFinalRule
from uniproxy.utils import maybe_map_to_tag, maybe_to_str

from .base import AbstractSingBox, BaseDnsServer, BaseInbound, BaseOutbound, BaseRuleSet
from .http_clients import HttpClient
from .route_rules import Rule


@define(hash=True)
class InlineRuleSet(BaseRuleSet):
    rules: Sequence[Rule]

    type: Literal["inline"] = "inline"


@define(hash=True)
class LocalRuleSet(BaseRuleSet):
    path: str

    format: Literal["binary", "source"]

    type: Literal["local"] = "local"

    def __attrs_post_init__(self) -> None:
        if self.format == "source" and not self.path.endswith("json"):
            raise ValueError(
                f"Invalid path for rule-set: {self.path}. Must end with '.json' for source format."
            )
        if self.format == "binary" and not self.path.endswith("srs"):
            raise ValueError(
                f"Invalid path for rule-set: {self.path}. Must end with '.srs' for binary format."
            )


@define(hash=True)
class RemoteRuleSet(BaseRuleSet):
    url: str
    format: Literal["binary", "source"] | None = None

    update_interval: float | None = None
    http_client: HttpClient | None = None

    # download_detour: BaseOutbound | str | None = field(
    #     default=None, converter=maybe_to_str
    # )
    # """
    # Tag of the outbound to download rule-set.

    # > Deprecated in sing-box 1.14.0
    # >
    # > `download_detour` is deprecated in sing-box 1.14.0 and will be removed in
    # > sing-box 1.16.0, use `http_client` instead.
    # """

    type: Literal["remote"] = "remote"

    def __attrs_post_init__(self) -> None:
        if self.format is None and self.url.endswith("json"):
            self.format = "source"
        elif self.format == "source" and not self.url.endswith("json"):
            raise ValueError(
                f"Invalid url for rule-set: {self.url}. Must end with '.json' for source format."
            )

        if self.format is None and self.url.endswith("srs"):
            self.format = "binary"
        elif self.format == "binary" and not self.url.endswith("srs"):
            raise ValueError(
                f"Invalid url for rule-set: {self.url}. Must end with '.srs' for binary format."
            )


type RuleSet = InlineRuleSet | LocalRuleSet | RemoteRuleSet


@define
class Route(AbstractSingBox):
    rules: Sequence[Rule]
    """List of [[Rule]]"""

    rule_set: Sequence[BaseRuleSet] | None = field(
        default=None, converter=maybe_map_to_tag
    )
    """List of [[rule-set]]"""

    final: BaseOutbound | str | None = field(default=None, converter=maybe_map_to_tag)
    """Default outbound tag. the first outbound will be used if empty."""

    auto_detect_interface: bool | None = None
    """
    > [!WARN] Only supported on Linux, Windows and macOS.

    Bind outbound connections to the default NIC by default to prevent routing loops under tun.

    Takes no effect if `outbound.bind_interface` is set.
    """

    override_android_vpn: bool | None = None
    """
    > [!WARN] Only supported on Android.

    Accept Android VPN as upstream NIC when `auto_detect_interface` enabled.
    """

    default_interface: str | None = None
    """
    > [!WARN] Only supported on Linux, Windows and macOS.

    Bind outbound connections to the specified NIC by default to prevent routing loops under tun.

    Takes no effect if `auto_detect_interface` is set.
    """

    default_mark: int | None = None
    """
    > [!WARN] Only supported on Linux.

    Set routing mark by default.

    Takes no effect if `outbound.routing_mark` is set.
    """

    default_http_client: HttpClient | str | None = field(
        default=None, converter=maybe_map_to_tag
    )
    """
    > [!NEW] Since sing-box 1.14.0

    Tag of the default HTTP Client used by remote rule-sets.

    If empty and `http_clients` is defined, the first HTTP client is used.
    """

    default_domain_resolver: BaseDnsServer | str | None = field(
        default=None, converter=maybe_to_str
    )
    """
    > [!NEW] Since sing-box 1.12.0

    Tag of target DNS server.
    """

    network_strategy: Literal["default", "hybrid", "fallback"] | None = None
    default_network_type: Literal["wifi", "cellular", "ethernet", "other"] | None = None
