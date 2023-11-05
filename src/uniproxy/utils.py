from configparser import ConfigParser
from typing import cast


def load_ini_without_section(s: str) -> dict:
    parser = ConfigParser()
    parser.read_string(f"[{parser.default_section}]\n{s}")
    return cast(dict, parser.defaults())
