from abc import ABC, abstractmethod


class AsClashTrait(ABC):
    @abstractmethod
    def __as_clash__(self): ...


class AbstractClash(ABC):
    """
    Abstract Clash class

    All Clash classes should inherit from this class.
    """

    __uniproxy_impl__ = "clash"
