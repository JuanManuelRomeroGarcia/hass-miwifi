"""Regression tests for mesh client counting and parent attribution."""

from custom_components.miwifi.updater import _ap_macs_by_ip, _find_leaf


def test_ap_macs_by_ip_uses_active_address() -> None:
    response = {
        "list": [
            {
                "isap": 1,
                "mac": "02:00:00:00:00:01",
                "ip": [
                    {"ip": "192.0.2.20", "active": 0},
                    {"ip": "192.0.2.21", "active": 1},
                ],
            }
        ]
    }

    assert _ap_macs_by_ip(response) == {
        "192.0.2.21": "02:00:00:00:00:01",
    }


def test_find_leaf_walks_nested_topology() -> None:
    graph = {
        "leafs": [
            {
                "ip": "192.0.2.2",
                "leafs": [{"ip": "192.0.2.3", "onlines": 4}],
            }
        ]
    }

    assert _find_leaf(graph, "192.0.2.3") == {
        "ip": "192.0.2.3",
        "onlines": 4,
    }


def test_find_leaf_ignores_invalid_leaf_lists() -> None:
    assert _find_leaf({"leafs": None}, "192.0.2.3") is None
    assert _find_leaf({"leafs": 1}, "192.0.2.3") is None
