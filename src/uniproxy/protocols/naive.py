from __future__ import annotations

from typing import Literal

from attrs import frozen
from uniproxy.typing import ProtocolType

from .base import BaseProtocol


@frozen
class NaiveProtocol(BaseProtocol):
    ...
