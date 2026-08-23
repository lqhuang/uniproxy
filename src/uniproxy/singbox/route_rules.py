from __future__ import annotations

from typing import Literal, Sequence

from attrs import define, field

from uniproxy.utils import maybe_map_to_tag, to_tag

from .base import BaseRule
from .typing import NetworkConn, NetworkProtocol, SniffProtocol

#
# Route Rule
#

type RoutePreferredBy = Literal["tailscale", "wireguard", "bridge"]

type FinalActionType = Literal["route", "reject", "hijack-dns"]
type NonFinalActionType = Literal["route-options", "sniff", "resolve"]
type RuleActionType = FinalActionType | NonFinalActionType


class BaseFinalActionRule(BaseRule): ...


class BaseNonFinalActionRule(BaseRule): ...


@define(slots=False)
class RouteOptionFieldsMixin:
    inbound: Sequence[str] | None = field(default=None, converter=maybe_map_to_tag)
    ip_version: Literal["4", "6", None] = None
    auth_user: str | Sequence[str] | None = None
    protocol: SniffProtocol | Sequence[SniffProtocol] | None = None
    client: str | Sequence[str] | None = None

    network: NetworkProtocol | Sequence[NetworkProtocol] | None = None
    domain: str | Sequence[str] | None = None
    domain_suffix: str | Sequence[str] | None = None
    domain_keyword: str | Sequence[str] | None = None
    domain_regex: str | Sequence[str] | None = None

    ip_cidr: str | Sequence[str] | None = None
    ip_is_private: bool | None = None
    source_ip_cidr: Sequence[str] | None = None
    source_ip_is_private: bool | None = None
    source_port: int | Sequence[int] | None = None
    source_port_range: str | Sequence[str] | None = None
    port: int | Sequence[int] | None = None
    port_range: str | Sequence[str] | None = None

    process_name: str | Sequence[str] | None = None
    process_path: str | Sequence[str] | None = None
    process_path_regex: str | Sequence[str] | None = None
    package_name: str | Sequence[str] | None = None
    package_name_regex: str | Sequence[str] | None = None

    user: str | Sequence[str] | None = None
    user_id: int | Sequence[int] | None = None

    network_type: NetworkConn | Sequence[NetworkConn] | None = None
    network_is_expensive: bool | None = None
    network_is_constrained: bool | None = None
    interface_address: None = None
    network_interface_address: None = None
    default_interface_address: None = None

    source_mac_address: str | Sequence[str] | None = None
    source_hostname: str | Sequence[str] | None = None

    preferred_by: RoutePreferredBy | Sequence[RoutePreferredBy] | None = None
    """
    The tag of a rule or server that is preferred when multiple rules match.
    """

    wifi_ssid: str | Sequence[str] | None = None
    wifi_bssid: str | Sequence[str] | None = None

    rule_set: str | Sequence[str] | None = field(
        default=None, converter=maybe_map_to_tag
    )
    rule_set_ip_cidr_match_source: bool | None = None
    invert: bool | None = None

    # Deprecated
    # rule_set_ipcidr_match_source


@define(slots=False)
class _RouteRule:
    outbound: str = field(converter=to_tag)


@define
class RouteRule(RouteOptionFieldsMixin, _RouteRule, BaseFinalActionRule):
    action: Literal["route"] = "route"


@define(slots=False)
class _RejectRule:
    method: Literal["default", "drop"] | None = None
    """
    - `default`: Reply with TCP RST for TCP connections, and ICMP port unreachable for UDP packets.
    - `drop`: Drop packets.

    `default` by default
    """

    no_drop: bool | None = None
    """
    If not enabled, `method` will be temporarily overwritten to `drop` after 50 triggers in 30s.

    Not available when `method` is set to drop.
    """


@define
class RejectRule(RouteOptionFieldsMixin, _RejectRule, BaseFinalActionRule):
    """
    https://sing-box.sagernet.org/configuration/route/rule_action/#reject

    ```json
    {
        "action": "reject",
        "method": "default", // default
        "no_drop": false
    }
    ```

    Action `reject` rejects connections

    The specified method is used for reject tun connections if `sniff` action has not been performed yet.

    For non-tun connections and already established connections, will just be closed.
    """

    action: Literal["reject"] = "reject"


@define
class HijackDnsRule(BaseFinalActionRule):
    """
    https://sing-box.sagernet.org/configuration/route/rule_action/#hijack-dns

    ```json
    {
      "action": "hijack-dns"
    }
    ```
    """

    protocol: Literal["dns"] = "dns"
    action: Literal["hijack-dns"] = "hijack-dns"


@define
class SniffRule(BaseNonFinalActionRule):
    """
    Example
    =======

    ```json
    {
        "action": "sniff",
        "sniffer": [],
        "timeout": ""
    }
    ```

    `sniff` performs protocol sniffing on connections.

    For deprecated `inbound.sniff` options, it is considered to `sniff()` performed before routing.

    Ref
    ===

    - https://sing-box.sagernet.org/configuration/route/rule_action/#sniff
    """

    sniffer: Sequence[SniffProtocol] | None = None
    """
    Enabled sniffers.

    All sniffers enabled by default.

    Available protocol values an be found on in [[Protocol Sniff]]
    """

    timeout: str | None = None
    """
    Timeout for sniffing.

    `300ms` is used by default.
    """

    action: Literal["sniff"] = "sniff"


type Rule = RouteRule | RejectRule | HijackDnsRule | SniffRule
