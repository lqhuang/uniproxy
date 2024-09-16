from uniproxy.surge.proxy_groups import (
    FallBackGroup,
    LoadBalanceGroup,
    SelectGroup,
    UrlTestGroup,
)


def test_select_group():
    select = SelectGroup(name="select", proxies=[])


def test_auto_group():
    auto = UrlTestGroup(name="auto", proxies=[])


def test_fallback_group(): ...


def test_load_balance_group(): ...
