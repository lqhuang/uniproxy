from __future__ import annotations

from typing import Any, Literal, Sequence
from uniproxy.typing import ServerAddress

from attrs import define, field

from uniproxy.abc import AbstractClash
from uniproxy.utils import maybe_map_to_str


@define
class BaseProtocol(AbstractClash):
    name: str
    server: ServerAddress
    port: int

    def __str__(self) -> str:
        return str(self.name)

    @classmethod
    def from_uniproxy(cls, protocol: Any, **kwargs) -> Any:
        raise NotImplementedError()

    def to_uniproxy(self, **kwargs) -> Any:
        raise NotImplementedError()


@define
class BaseProxyProvider(AbstractClash):
    name: str

    def __str__(self) -> str:
        return str(self.name)


@define
class BaseRule(AbstractClash): ...


@define
class BaseBasicRule(BaseRule):
    matcher: RuleProviderLike
    policy: ProtocolLike

    def __str__(self) -> str:
        if hasattr(self, "type"):
            return f"{self.type.upper()},{str(self.matcher)},{str(self.policy)}"  # type: ignore
        else:
            raise NotImplementedError


@define
class FinalRule(BaseRule):
    policy: ProtocolLike
    type: Literal["final"] = "final"

    def __str__(self) -> str:
        return f"MATCH,{self.policy}"


@define
class BaseProxyGroup(AbstractClash):
    name: str
    proxies: Sequence[ProtocolLike] | None = field(
        default=None, converter=maybe_map_to_str
    )
    use: Sequence[BaseRuleProvider | str] | None = field(
        default=None, converter=maybe_map_to_str
    )

    disable_udp: bool = False

    url: str = "https://www.gstatic.com/generate_204"
    interval: float = 120  # seconds
    lazy: bool = True

    filter: str | None = None
    # timeout: float = 5  # seconds

    def __str__(self) -> str:
        return str(self.name)

    def __attrs_post_init__(self):
        if self.proxies is None and self.use is None:
            raise ValueError("Either proxies or use must be provided")

    @classmethod
    def from_uniproxy(cls, protocol: Any, **kwargs) -> Any:
        raise NotImplementedError()

    def to_uniproxy(self, **kwargs) -> Any:
        raise NotImplementedError()


@define
class BaseRuleProvider:
    name: str

    def __str__(self) -> str:
        return str(self.name)


ProtocolLike = BaseProtocol | BaseProxyGroup | BaseProxyProvider | str
RuleProviderLike = BaseRuleProvider | str
