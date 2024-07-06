from __future__ import annotations

from typing import Mapping
from uniproxy.typing import ProtocolType

from .base import BaseProtocol
from .protocols import ShadowsocksProtocol, VmessProtocol

PROTOCOLS_MAPPER: Mapping[ProtocolType, BaseProtocol] = {
    "shadowsocks": ShadowsocksProtocol,
    "vmess": VmessProtocol,
}
