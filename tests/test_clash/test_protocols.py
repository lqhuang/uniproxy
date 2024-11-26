from __future__ import annotations

from functools import partial
from textwrap import dedent

from ruamel.yaml import YAML
from xattrs import asdict
from xattrs.converters import to_kebab
from xattrs.filters import exclude_if_none
from xattrs.preconf.yaml import _yaml_loads

from uniproxy.clash.protocols import (
    ShadowsocksProtocol,
    Socks5Protocol,
    VmessProtocol,
    VmessWsTransport,
)

yaml = YAML()
yaml_loads = partial(_yaml_loads, _ruamel_yaml=yaml)


def test_proxy_socks5():
    name = "proxy-socks5"
    socks5 = Socks5Protocol(name=name, server="localhost", port=1080)
    clash_config = dedent(
        f"""
        name: "{name}"
        type: socks5
        server: localhost
        port: 1080
        udp: true
        """
    )
    assert asdict(
        socks5, filter=exclude_if_none, key_serializer=to_kebab
    ) == yaml_loads(clash_config)


def test_proxy_socks5__tls():
    name = "proxy-socks5"
    socks5 = Socks5Protocol(
        name=name,
        server="10.0.0.1",
        port=1080,
        username="user",
        password="pass",
        tls=True,
        skip_cert_verify=True,
    )
    clash_config = dedent(
        f"""
        name: "{name}"
        type: socks5
        server: 10.0.0.1
        port: 1080
        username: user
        password: pass
        tls: true
        skip-cert-verify: true
        udp: true
        """
    )
    assert asdict(
        socks5, filter=exclude_if_none, key_serializer=to_kebab
    ) == yaml_loads(clash_config)


def test_proxy_vmess():
    vmess = VmessProtocol(
        name="proxy-vmess",
        server="localhost",
        port=1080,
        uuid="692b215d-ee58-4a4c-a430-b686c9a658fe",
        alter_id=32,
        cipher="auto",
        udp=True,
    )

    clash_config = dedent(
        """
        name: proxy-vmess
        type: vmess
        server: localhost
        port: 1080
        uuid: 692b215d-ee58-4a4c-a430-b686c9a658fe
        alterId: 32
        cipher: auto
        udp: true
        """
    )
    assert asdict(vmess, filter=exclude_if_none, key_serializer=to_kebab) == yaml_loads(
        clash_config
    )


def test_proxy_vmess__ws():
    vmess = VmessProtocol(
        name="proxy-vmess",
        server="localhost",
        port=1080,
        uuid="692b215d-ee58-4a4c-a430-b686c9a658fe",
        alter_id=32,
        cipher="auto",
        udp=True,
        tls=True,
        skip_cert_verify=True,
        servername="example.com",
        network="ws",
        ws_opts=VmessWsTransport(path="/ws-path"),
    )

    clash_config = dedent(
        """
        name: proxy-vmess
        type: vmess
        server: localhost
        port: 1080
        uuid: 692b215d-ee58-4a4c-a430-b686c9a658fe
        alterId: 32
        cipher: auto
        udp: true
        tls: true
        skip-cert-verify: true
        servername: example.com
        network: ws
        ws-opts:
            path: /ws-path
        """
    )
    assert asdict(vmess, filter=exclude_if_none, key_serializer=to_kebab) == yaml_loads(
        clash_config
    )
