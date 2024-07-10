from __future__ import annotations

from typing import Any, Iterable, Protocol, cast

from configparser import ConfigParser


def load_ini_without_section(s: str) -> dict:
    parser = ConfigParser()
    parser.read_string(f"[{parser.default_section}]\n{s}")
    return cast(dict, parser.defaults())


class HasName(Protocol):
    name: str


def to_name(x: str | HasName) -> str:
    if isinstance(x, str):
        return x
    else:
        return x.name


def map_to_name(xs: Iterable[HasName | str] | None) -> list[str] | None:
    if xs is None:
        return None
    return [to_name(each) for each in xs]


def map_to_str(xs: Iterable[Any | str] | None) -> list[str] | None:
    if xs is None:
        return None
    return [str(each) for each in xs]
