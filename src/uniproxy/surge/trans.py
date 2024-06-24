from uniproxy.typing import ProtocolType

from .base import BaseProtocol
from .protocols import ShadowsocksProtocol, VmessProtocol

PROTOCOLS_MAPPER: dict[ProtocolType, BaseProtocol] = {
    "shadowsocks": ShadowsocksProtocol,
    "vmess": VmessProtocol,
}
