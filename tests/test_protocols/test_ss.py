from __future__ import annotations

import random
import string
from functools import partial
from textwrap import dedent

import pytest
from ruamel.yaml import YAML
from xattrs import asdict, evolve
from xattrs.converters import to_kebab
from xattrs.filters import exclude_if_none
from xattrs.preconf.yaml import _yaml_loads

from uniproxy.clash.protocols import ShadowsocksProtocol as ClashShadowsocksProtocol
from uniproxy.clash.protocols import make_protocol_from_uniproxy as make_clash_protocol
from uniproxy.protocols import ShadowsocksObfsPlugin, ShadowsocksProtocol
from uniproxy.surge.protocols import ShadowsocksProtocol as SurgeShadowsocksProtocol
from uniproxy.surge.protocols import make_protocol_from_uniproxy as make_surge_protocol
from uniproxy.utils import load_ini_without_section

yaml = YAML()
yaml_loads = partial(_yaml_loads, _ruamel_yaml=yaml)

_clash_as_dict = partial(asdict, filter=exclude_if_none, key_serializer=to_kebab)


@pytest.fixture(scope="module")
def ss_config_obfs():
    port = random.randint(1024, 65535)
    password = "".join(random.choices(string.ascii_letters, k=10))
    plugin = "obfs"
    name = "".join(random.choices(string.ascii_letters, k=10))
    ss = {
        "remarks": name,
        "server": "localhost",
        "server_port": port,
        "password": password,
        "method": "aes-128-gcm",
        "plugin": plugin,
        "network": "tcp_and_udp",
        "plugin_opts": "obfs=http;obfs-host=www.microsoft.com",
    }

    clash_config = dedent(f"""
        name: "{name}"
        type: ss
        server: localhost
        port: {port}
        cipher: aes-128-gcm
        password: "{password}"
        udp: true
        plugin: {plugin}
        plugin-opts: {{ mode: http, host: www.microsoft.com }}
    """)

    surge_config = f"{name} = ss, localhost, {port}, encrypt-method=aes-128-gcm, password={password}, udp-relay=true, obfs=http, obfs-host=www.microsoft.com"
    return ss, clash_config, surge_config


class TestShadowsocksProtocol:
    def test_surge(self):
        name = "proxy-ss"
        ss = SurgeShadowsocksProtocol(
            name=name,
            server="localhost",
            port=1080,
            encrypt_method="aes-256-gcm",
            password="pass",
            udp_relay=True,
        )

        surge_config = f"{name} = ss, localhost, 1080, encrypt-method=aes-256-gcm, password=pass, udp-relay=true"
        assert asdict(ss) == load_ini_without_section(surge_config)

    def test_clash(self):
        ss = ClashShadowsocksProtocol(
            name="proxy-ss",
            server="localhost",
            port=1080,
            cipher="aes-256-gcm",
            password="pass",
            udp=True,
        )

        clash_config = dedent(
            """
            name: "proxy-ss"
            type: "ss"
            server: localhost
            port: 1080
            cipher: "aes-256-gcm"
            password: "pass"
            udp: true
            """
        )
        assert _clash_as_dict(ss) == yaml_loads(clash_config)

    def test_from_uniproxy(self, ss_config_obfs):
        ss_config, clash_config, surge_config = ss_config_obfs

        kv_pairs = ss_config["plugin_opts"].split(";")
        plugin_opts = {k: v for k, v in [p.split("=") for p in kv_pairs]}

        ss = ShadowsocksProtocol(
            name=ss_config["remarks"],
            server=ss_config["server"],
            port=ss_config["server_port"],
            method=ss_config["method"],
            password=ss_config["password"],
            network=ss_config.get("network", "tcp_and_udp"),
            plugin=ShadowsocksObfsPlugin(
                command=ss_config["plugin"],
                obfs=plugin_opts["obfs"],
                obfs_host=plugin_opts["obfs-host"],
            ),
        )

        clash_ss = make_clash_protocol(ss)
        assert _clash_as_dict(clash_ss) == yaml_loads(clash_config)

        surge_ss = make_surge_protocol(ss)

        assert asdict(
            evolve(surge_ss, name=surge_ss.name.lower())
        ) == load_ini_without_section(surge_config)
