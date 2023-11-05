from proxy_groups import SelectGroup, AutoGroup, FallBackGroup, LoadBalanceGroup


def test_select_group():
    select = SelectGroup(name="select", proxies=[])


def test_auto_group():
    auto = AutoGroup(name="auto", proxies=[])


def test_fallback_group():
    ...


def test_load_balance_group():
    ...
