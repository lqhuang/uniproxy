from __future__ import annotations

from attrs import frozen

from .base import BaseProxyGroup, SurgeGroupType


@frozen
class SelectGroup(BaseProxyGroup):
    type = "select"

    def as_dict(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        return {self.name: f"{self.type}, {proxies}"}


@frozen
class UrlTestGroup(BaseProxyGroup):
    interval: float = 60  # seconds
    tolerance: float = 300  # milliseconds
    timeout: float = 5  # seconds
    evaluate_before_use: bool = False
    """
    By default, when the Automatic Testing policy group is used for the first time, in order not to affect the request, it will first access using the first policy in the policy group while triggering a test of the policy group.

    If this option is enabled, then when using the Automatic Testing policy group for the first time, it will trigger a test of the policy group and wait until testing is finished before making requests with selected results.
    """

    url: str = "https://www.gstatic.com/generate_204"
    type = "url-test"

    def as_dict(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        opts = f"interval={self.interval}, tolerance={self.tolerance}, timeout={self.timeout}"
        return {self.name: f"{self.type}, {proxies}, {opts}"}


@frozen
class FallBackGroup(BaseProxyGroup):
    interval: float = 120  # milliseconds
    timeout: float = 5  # seconds

    type = "fallback"

    def as_dict(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        opts = f"interval={self.interval}, timeout={self.timeout}"
        return {self.name: f"{self.type}, {proxies}, {opts}"}


@frozen
class LoadBalanceGroup(BaseProxyGroup):
    persistent: bool = False

    type = "load-balance"

    def as_dict(self) -> dict[str, str]:
        proxies = ", ".join((p.name for p in self.proxies))
        opts = f"persistent={self.persistent}"
        return {self.name: f"{self.type}, {proxies}, {opts}"}


@frozen
class ExternalGroup(BaseProxyGroup):
    using_type: SurgeGroupType
    policy_path: str

    update_interval: float | None = 21600  # 6 hours
    """The update interval in seconds. Only meaningful when the path is a URL."""

    policy_regex_filter: str | None = None
    """Only use the policies that the regex matches the policy name."""

    external_policy_modifier: str | None = None
    """
    You may use this parameter to modify the parameters of external policies.
    For example, enabling TFO and changing the testing URL:

        external-policy-modifier="test-url=http://apple.com/,tfo=true"
    """

    type = "external"

    def __post_init__(self) -> None:
        if self.using_type == "external":
            raise ValueError("The using_type cannot be 'external'.")

    def as_dict(self) -> dict[str, str]:
        external_policy_modifier = (
            '"%s"' % self.external_policy_modifier.strip("'").strip('"')
            if self.external_policy_modifier is not None
            else None
        )
        conf = {
            "policy-path": self.policy_path,
            "update-interval": self.update_interval,
            "policy-regex-filter": self.policy_regex_filter,
            "external-policy-modifier": external_policy_modifier,
        }
        opts = ", ".join(f"{k}={v}" for k, v in conf.items() if v is not None)
        return {self.name: f"{self.using_type}, {opts}"}
