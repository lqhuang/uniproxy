from abc import ABC, abstractmethod


class AbstractClash(ABC):
    """
    Abstract Clash class

    All Clash classes should inherit from this class.
    """

    __uniproxy_impl__ = "clash"

ProtocolType = Literal[
    "http",
    "https",
    "socks5",
    "socks5-tls",
    "ss",
    "vmess",
    "trojan",
    "tuic",
    "hysteria",
]

class GroupType(StrEnum):
    SELECT = "select"
    URL_TEST = "url-test"
    FALLBACK = "fallback"
    LOAD_BALANCE = "load-balance"
    EXTERNAL = "external"


class BaseClashProtocol(AbstractClash):
    name: str
    type: ProtocolType

    def __str__(self) -> str:
        return str(self.name)

@frozen
class BaseClashProxyGroup(AbstractClash):
    name: str
    proxies: Iterable[BaseClashProtocol | BaseClashProxyGroup]
    type: GroupType
    url: str = "http://www.gstatic.com/generate_204"
    udp: bool = True
    lazy: bool = True  # clash only

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