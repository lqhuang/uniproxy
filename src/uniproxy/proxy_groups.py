from __future__ import annotations

from typing import Iterable, Literal

from enum import StrEnum

from attrs import frozen

from uniproxy.base import BaseProtocol


@frozen
class BaseProxyGroup:
    name: str
    proxies: Iterable[BaseProtocol | BaseProxyGroup]
    type: GroupType
    url: str = "http://www.gstatic.com/generate_204"
    udp: bool = True
    lazy: bool = True  # clash only

    @classmethod
    def from_toml(cls) -> BaseProxyGroup: ...

    def as_clash(self) -> dict:
        raise NotImplementedError

    def as_surge(self) -> dict[str, str]:
        raise NotImplementedError

    @property
    def disable_udp(self) -> bool:
        """(Clash) Disable UDP for this group."""
        return not self.udp

    @property
    def include_other_group(self) -> tuple[BaseProxyGroup, ...]:
        """(Surge) Include other groups in this group."""
        return tuple(
            group for group in self.proxies if isinstance(group, BaseProxyGroup)
        )


class GroupType(StrEnum):
    SELECT = "select"
    URL_TEST = "url-test"
    FALLBACK = "fallback"
    LOAD_BALANCE = "load-balance"
    EXTERNAL = "external"


@frozen
class SelectGroup(BaseProxyGroup):
    type: Literal[GroupType.SELECT] = GroupType.SELECT

    def as_surge(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        return {self.name: f"{self.type}, {proxies}"}


@frozen
class AutoGroup(BaseProxyGroup):
    type: Literal[GroupType.URL_TEST] = GroupType.URL_TEST
    filter: str | None = None
    interval: float = 60  # seconds
    tolerance: float = 300  # milliseconds
    timeout: float = 5  # seconds

    def as_surge(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        opts = f"interval={self.interval}, tolerance={self.tolerance}, timeout={self.timeout}"
        return {self.name: f"{self.type}, {proxies}, url={self.url}, {opts}"}


@frozen
class FallBackGroup(BaseProxyGroup):
    type: Literal[GroupType.FALLBACK] = GroupType.FALLBACK
    filter: str | None = None
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds

    def as_surge(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        opts = f"interval={self.interval}, timeout={self.timeout}"
        return {self.name: f"{self.type}, {proxies}, url={self.url}, {opts}"}


@frozen
class LoadBalanceGroup(BaseProxyGroup):
    type: Literal[GroupType.LOAD_BALANCE] = GroupType.LOAD_BALANCE
    strategy: Literal["consistent-hashing", "round-robin"] | None = None

    @property
    def persistent(self) -> bool:
        """(Surge) Enable persistent connection."""
        return self.strategy == "consistent-hashing" if self.strategy else False

    def as_surge(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        opts = f"persistent={self.persistent}"
        return {self.name: f"{self.type}, {proxies}, {opts}"}


@frozen
class ExternalGroup(BaseProxyGroup):
    # FIXME: Compose Other Group instead of add `using_type` in ExternalGroup

    proxies: Iterable[BaseProtocol | BaseProxyGroup] = ()
    type: Literal[GroupType.EXTERNAL] = GroupType.EXTERNAL
    using_type: GroupType = GroupType.SELECT
    policy_path: str | None = None

    # The update interval in seconds. Only meaningful when the path is a URL.
    update_interval: float | None = 21600  # 6 hours

    # Only use the policies that the regex matches the policy name.
    policy_regex_filter: str | None = None

    # You may use this parameter to modify the parameters of external policies.
    # For example, enabling TFO and changing the testing URL:
    #
    #     external-policy-modifier="test-url=http://apple.com/,tfo=true"
    external_policy_modifier: str | None = None

    def as_surge(self) -> dict[str, str]:
        # opts = f"interval={self.interval}, timeout={self.timeout}"
        if self.external_policy_modifier is not None:
            external_policy_modifier = (
                f", external-policy-modifier={self.external_policy_modifier}"
            )
        else:
            external_policy_modifier = ""

        all_opts = (
            f"{self.using_type}, policy-path={self.policy_path}, "
            f"update-interval={self.update_interval}"
            f"{external_policy_modifier}"
        )
        return {self.name: all_opts}
