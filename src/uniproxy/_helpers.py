from __future__ import annotations

from typing import Callable, Sequence, TypeVar

from itertools import chain
from operator import itemgetter

from uniproxy.base import BaseProtocol, BaseProxyGroup, BaseProxyProvider, ProtocolLike


def split_uniproxy_protocol_like(proxies: Sequence[ProtocolLike | str]) -> tuple[
    list[tuple[int, BaseProtocol]],
    list[tuple[int, BaseProxyProvider]],
    list[tuple[int, BaseProxyGroup]],
]:
    """Split a list of proxies into separate lists based on their type.

    Args:
      proxies (Sequence[ProtocolLike | str]):
        A sequence of proxies.

    Returns:
      tuple[list[(int, BaseProtocol)], list[(int, BaseProxyProvider)], list[(int, BaseProxyGroup)]]:
        A tuple containing three lists:

        - A list of tuples containing the index and the BaseProtocol objects from the input proxies.
        - A list of tuples containing the index and the BaseProxyProvider objects from the input proxies.
        - A list of tuples containing the index and the BaseProxyGroup objects from the input proxies.

    Raises:
      TypeError: If an unknown type is encountered in the input proxies.
    """
    protocols = []
    providers = []
    groups = []
    for i, each in enumerate(proxies):
        if isinstance(each, BaseProtocol):
            protocols.append((i, each))
        elif isinstance(each, BaseProxyProvider):
            providers.append((i, each))
        elif isinstance(each, BaseProxyGroup):
            groups.append((i, each))
        else:
            raise TypeError(f"Unknown type: {type(each)}")
    return (protocols, providers, groups)


T = TypeVar("T")


def merge_pairs_by_key(
    *seqs: Sequence[tuple[int, T]], key: Callable | None = None
) -> list[T]:
    """Merge multiple sequences of pair like (index, object) into a single list.

    Args:
      *seqs: Sequence[tuple[int, Any]],

    Returns:
      list[Any]:
        A list of sorted objects.
    """
    if key is None:
        key = itemgetter(0)
    return [each[1] for each in sorted(chain(*seqs), key=key)]
