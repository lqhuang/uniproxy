from __future__ import annotations

from typing import Any, Iterable, Protocol, Sequence, cast

from configparser import ConfigParser


def load_ini_without_section(s: str) -> dict:
    parser = ConfigParser()
    parser.read_string(f"[{parser.default_section}]\n{s}")
    return cast(dict, parser.defaults())


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


def map_to_name(xs: Iterable[HasName | str] | None) -> Sequence[str] | None:
    if xs is None:
        return None
    return [to_name(each) for each in xs]


def flatmap_to_tag(
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


def flatmap_to_name(
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


def map_to_str(xs: Iterable[Any | str] | None) -> Sequence[str] | None:
    if xs is None:
        return None
    return [str(each) for each in xs]
