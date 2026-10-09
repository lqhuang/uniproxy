from __future__ import annotations

from abc import ABC, abstractmethod


class BaseTaggable(ABC):
    @property
    @abstractmethod
    def to_tag(self) -> str:
        raise NotImplementedError()
