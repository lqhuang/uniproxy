from __future__ import annotations

from textwrap import dedent

from proxies import ShadowsocksProxy, Socks5Proxy, VmessProxy, VmessWSOpt
from utils import load_ini_without_section
from yaml import safe_load


def test_proxy_socks5():
    name = "proxy-socks5"
    socks5 = Socks5Proxy(name=name, host="localhost", port=1080)

    clash_config = dedent(
        f"""
        name: "{name}"
        type: socks5
        server: localhost
        port: 1080
        udp: true
        """
    )
    assert socks5.as_clash() == safe_load(clash_config)

    surge_config = f"{name} = socks5, localhost, 1080"
    assert socks5.as_surge() == load_ini_without_section(surge_config)


def test_proxy_socks5__tls():
    name = "proxy-socks5"
    socks5 = Socks5Proxy(
        name=name,
        host="10.0.0.1",
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
    assert socks5.as_clash() == safe_load(clash_config)
    surge_config = (
        f"{name} = socks5-tls, 10.0.0.1, 1080, user, pass, skip-common-name-verify=true"
    )
    assert socks5.as_surge() == load_ini_without_section(surge_config)


def test_proxy_ss():
    ss = ShadowsocksProxy(
        name="proxy-ss",
        host="localhost",
        port=1080,
        method="aes-256-gcm",
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
    assert ss.as_clash() == safe_load(clash_config)

    surge_config = "proxy-ss = ss, localhost, 1080, encrypt-method=aes-256-gcm, password=pass, udp-relay=true"
    assert ss.as_surge() == load_ini_without_section(surge_config)


def test_proxy_vmess():
    vmess = VmessProxy(
        name="proxy-vmess",
        host="localhost",
        port=1080,
        uuid="692b215d-ee58-4a4c-a430-b686c9a658fe",
        alter_id=32,
        method="auto",
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
    assert vmess.as_clash() == safe_load(clash_config)

    surge_config = "proxy-vmess = vmess, localhost, 1080, username=692b215d-ee58-4a4c-a430-b686c9a658fe, encrypt-method=auto"
    assert vmess.as_surge() == load_ini_without_section(surge_config)


def test_proxy_vmess__ws():
    vmess = VmessProxy(
        name="proxy-vmess",
        host="localhost",
        port=1080,
        uuid="692b215d-ee58-4a4c-a430-b686c9a658fe",
        alter_id=32,
        method="auto",
        udp=True,
        tls=True,
        skip_cert_verify=True,
        sni="example.com",
        ws=VmessWSOpt(path="/ws-path"),
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
    assert vmess.as_clash() == safe_load(clash_config)

    surge_config = (
        "proxy-vmess = vmess, localhost, 1080, "
        "username=692b215d-ee58-4a4c-a430-b686c9a658fe, encrypt-method=auto, "
        "skip-common-name-verify=true, sni=example.com, ws=true, ws-path=/ws-path"
    )
    assert vmess.as_surge() == load_ini_without_section(surge_config)
