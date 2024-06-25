from __future__ import annotations

from typing import Mapping
from uniproxy.typing import ProtocolType

from .base import BaseProtocol as SurgeBaseProtocol
from .protocols import ShadowsocksProtocol, VmessProtocol

PROTOCOLS_MAPPER: Mapping[ProtocolType, SurgeBaseProtocol] = {
    "shadowsocks": ShadowsocksProtocol,
    "vmess": VmessProtocol,
}
