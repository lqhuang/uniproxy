from __future__ import annotations

from abc import ABC, abstractmethod
from functools import cached_property


class BaseTaggable(ABC):
    @cached_property
    @abstractmethod
    def to_tag(self) -> str:
        raise NotImplementedError()
