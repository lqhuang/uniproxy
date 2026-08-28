from __future__ import annotations

from typing import Any, Iterable, Protocol, Sequence, cast

import binascii
from base64 import b64decode
from configparser import ConfigParser
from functools import cached_property


def load_ini_without_section(s: str) -> dict[str, Any]:
    parser = ConfigParser()
    parser.read_string(f"[{parser.default_section}]\n{s}")
    return cast(dict[str, Any], parser.defaults())


def padded_b64decode(b64: str) -> bytes:
    try:
        return b64decode(b64)
    except binascii.Error:
        padding = "=" * ((4 - len(b64) % 4) % 4)
        return b64decode(b64 + padding)


class HasName(Protocol):
    name: str


class HasTag(Protocol):
    tag: str


class Taggable(Protocol):
    @cached_property
    def to_tag(self) -> str: ...


def to_tag(x: Taggable | str) -> str:
    if isinstance(x, str):
        return x
    else:
        try:
            return x.to_tag
        except AttributeError:
            raise TypeError(
                f"Object {x} ({type(x)}) does not have a 'to_tag' property or not an instance of 'str' type."
            )


def map_to_tag(xs: Iterable[Taggable | str]) -> tuple[str, ...]:
    return tuple(to_tag(each) for each in xs)


def maybe_to_tag(x: Taggable | str | None) -> str | None:
    return to_tag(x) if x is not None else None


def to_name(x: HasName | str) -> str:
    if isinstance(x, str):
        return x
    else:
        return x.name


def maybe_map_to_name(xs: Iterable[HasName | str] | None) -> Sequence[str] | None:
    if xs is None:
        return None
    return [to_name(each) for each in xs]


def flatmap_to_tag(xs: Iterable[Taggable | str] | None) -> tuple[str, ...]:
    return () if xs is None else tuple(to_tag(each) for each in xs)


def maybe_map_to_tag(
    xs: Iterable[Taggable | str] | Taggable | str | None,
) -> Sequence[str] | None:
    if xs is None:
        return None
    elif isinstance(xs, str):
        return xs
    elif isinstance(xs, Iterable):
        return [to_tag(each) for each in xs]
    else:
        return to_tag(xs)


def maybe_flatmap_to_name(
    xs: Iterable[HasName | str] | HasName | str | None,
) -> Sequence[str] | None:
    if xs is None:
        return None
    elif isinstance(xs, str):
        return xs
    elif isinstance(xs, Iterable):
        return [to_name(each) for each in xs]
    else:
        return to_name(xs)


def maybe_flatmap_to_str(
    xs: Any | str | Iterable[Any | str] | None,
) -> str | tuple[str, ...] | None:
    if xs is None:
        return None
    elif isinstance(xs, str):  # str is also Iterable
        return xs
    elif isinstance(xs, Iterable):
        return tuple(str(each) for each in xs)
    else:
        return str(xs)  # fallback to Any


def map_to_str(xs: Iterable[Any | str]) -> tuple[str, ...]:
    return tuple(str(each) for each in xs)


def flatmap_to_str(xs: Iterable[Any | str] | None) -> tuple[str, ...]:
    return () if xs is None else tuple(str(each) for each in xs)


def maybe_map_to_str(xs: Iterable[Any | str] | None) -> tuple[str, ...] | None:
    if xs is None:
        return None
    return tuple(str(each) for each in xs)


def maybe_to_str(x: Any | str | None) -> str | None:
    return str(x) if x is not None else None
