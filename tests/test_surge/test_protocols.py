from __future__ import annotations

from xattrs import asdict

from uniproxy.surge.protocols import (
    Socks5Protocol,
    SurgeTLS,
    VmessProtocol,
    VmessTransport,
)
from uniproxy.utils import load_ini_without_section


def test_proxy_socks5():
    name = "proxy-socks5"
    socks5 = Socks5Protocol(name=name, server="localhost", port=1080)
    surge_config = f"{name} = socks5, localhost, 1080"
    assert asdict(socks5) == load_ini_without_section(surge_config)


def test_proxy_socks5__tls():
    name = "proxy-socks5"
    socks5 = Socks5Protocol(
        name=name,
        server="10.0.0.1",
        port=1080,
        username="user",
        password="pass",
        tls=SurgeTLS(skip_cert_verify=True),
    )
    surge_config = (
        f"{name} = socks5-tls, 10.0.0.1, 1080, user, pass, skip-cert-verify=true"
    )
    assert asdict(socks5) == load_ini_without_section(surge_config)


def test_proxy_vmess():
    name = "proxy-vmess"
    vmess = VmessProtocol(
        name=name,
        server="localhost",
        port=1080,
        username="692b215d-ee58-4a4c-a430-b686c9a658fe",
        encrypt_method="auto",
    )
    surge_config = f"{name} = vmess, localhost, 1080, username=692b215d-ee58-4a4c-a430-b686c9a658fe, encrypt-method=auto"
    assert asdict(vmess) == load_ini_without_section(surge_config)


def test_proxy_vmess__ws():
    vmess = VmessProtocol(
        name="proxy-vmess",
        server="localhost",
        port=1080,
        username="692b215d-ee58-4a4c-a430-b686c9a658fe",
        encrypt_method="auto",
        tls=SurgeTLS(skip_cert_verify=True, sni="example.com"),
        transport=VmessTransport(path="/ws-path"),
    )
    surge_config = (
        "proxy-vmess = vmess, localhost, 1080, "
        "username=692b215d-ee58-4a4c-a430-b686c9a658fe, "
        "encrypt-method=auto, "
        "skip-cert-verify=true, sni=example.com, "
        "ws=true, ws-path=/ws-path"
    )
    assert asdict(vmess) == load_ini_without_section(surge_config)
