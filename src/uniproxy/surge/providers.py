from __future__ import annotations

from typing import Literal

from attrs import define

from uniproxy.providers import ProxyProvider as UniproxyProxyProvider

from .base import BaseProxyProvider
from .typing import SurgeGroupType


@define
class ExternalPoliciesProvider(BaseProxyProvider):
    using_type: SurgeGroupType
    policy_path: str
    """
    A policy group may import policies defined in an external file or from a URL.

    ```
    egroup = select, policy-path=proxies.txt
    ```

    This file contains a list of policies, just like the definition lines in the main profile.
    """
    update_interval: float | None = None
    """The update interval in seconds. Only meaningful when the path is a URL."""
    policy_regex_filter: str | None = None
    """Only use the policies that the regex matches the policy name."""
    external_policy_modifier: str | None = None
    """
    You may use this parameter to modify the parameters of external policies.
    For example, enabling TFO and changing the testing URL:

    ```
    external-policy-modifier="test-url=http://apple.com/,tfo=true"
    ```
    """

    type: Literal["external"] = "external"

    def __attrs_asdict__(self):
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

    @classmethod
    def from_uniproxy(
        cls, uniproxy: UniproxyProxyProvider, **kwargs
    ) -> ExternalPoliciesProvider:

        if "external_policy_modifier" in kwargs:
            external_policy_modifier = kwargs["external_policy_modifier"]
        else:
            external_policy_modifier = None

        return cls(
            name=uniproxy.name,
            using_type=uniproxy.type,
            policy_path=uniproxy.url,
            update_interval=uniproxy.interval,
            external_policy_modifier=external_policy_modifier,
        )
