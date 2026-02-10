from __future__ import annotations

from typing import Any, Iterable, Protocol, Sequence, cast

import binascii
from base64 import b64decode
from configparser import ConfigParser


def load_ini_without_section(s: str) -> dict:
    parser = ConfigParser()
    parser.read_string(f"[{parser.default_section}]\n{s}")
    return cast(dict, parser.defaults())


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


def to_tag(x: HasTag | str) -> str:
    if isinstance(x, str):
        return x
    else:
        return x.tag


def to_name(x: HasName | str) -> str:
    if isinstance(x, str):
        return x
    else:
        return x.name


def maybe_map_to_name(xs: Iterable[HasName | str] | None) -> Sequence[str] | None:
    if xs is None:
        return None
    return [to_name(each) for each in xs]


def maybe_flatmap_to_tag(
    xs: Iterable[HasTag | str] | HasTag | str | None,
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
) -> str | list[str] | None:
    if xs is None:
        return None
    elif isinstance(xs, str):  # str is also Iterable
        return xs
    elif isinstance(xs, Iterable):
        return [str(each) for each in xs]
    else:
        return str(xs)  # fallback to Any


def map_to_str(xs: Iterable[Any | str]) -> list[str]:
    return [str(each) for each in xs]


def maybe_map_to_str(xs: Iterable[Any | str] | None) -> list[str] | None:
    if xs is None:
        return None
    return [str(each) for each in xs]


def maybe_to_str(x: Any | str | None) -> str | None:
    return str(x) if x is not None else None
