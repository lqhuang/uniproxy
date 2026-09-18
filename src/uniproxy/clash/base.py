from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar
from uniproxy.typing import ServerAddress

from attrs import define, field

from uniproxy.utils import maybe_map_to_str


class AbstractMihomo:
    """
    Abstract Mihomo class

    All Mihomo classes should inherit from this class.
    """

    __uniproxy_impl__: ClassVar[str] = "mihomo"


@define
class BaseProtocol(AbstractMihomo):
    name: str
    server: ServerAddress
    port: int

    def __str__(self) -> str:
        return self.name


@define
class BaseProxyProvider(AbstractMihomo):
    name: str

    def __str__(self) -> str:
        return self.name


@define
class BaseRule(AbstractMihomo): ...


@define
class BaseBasicRule(BaseRule):
    matcher: RuleProviderLike
    policy: ProtocolLike

    def __str__(self) -> str:
        if hasattr(self, "type"):
            return f"{self.type.upper()},{self.matcher!s},{self.policy!s}"  # type: ignore
        else:
            raise NotImplementedError


@define
class BaseProxyGroup(AbstractMihomo):
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
        return self.name

    def __attrs_post_init__(self):
        if self.proxies is None and self.use is None:
            raise ValueError("Either proxies or use must be provided")


@define
class BaseRuleProvider:
    name: str

    def __str__(self) -> str:
        return self.name


type ProtocolLike = BaseProtocol | BaseProxyGroup | BaseProxyProvider | str
type RuleProviderLike = BaseRuleProvider | str
