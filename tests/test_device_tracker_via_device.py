"""Hanging a client off the node that serves it, on either core.

`via_device` names the parent by identifier. That stopped being a unique
reference the moment a device became the property of a single config entry, so
core 2026.9 takes the parent's row id as `via_device_id` and removes the tuple
in 2027.8. Both spellings have to keep working: this fork runs on installs older
than that.

The third case is the important one. Pointing at a device that does not exist is
what broke installs in 2025.12, and it is why the lookup exists at all: when the
node cannot be resolved, the answer is no link, not a dangling one.
"""

# pylint: disable=protected-access

from __future__ import annotations

from unittest.mock import MagicMock, patch

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.device_tracker import (
    _ensure_via_device_exists,
    _via_device_info,
)

MAC: str = "00:00:00:00:00:02"


class _Row:
    def __init__(self) -> None:
        self.id = "node_row_id"
        self.identifiers = {(DOMAIN, MAC)}


def test_a_recent_core_is_given_the_node_row_id() -> None:
    """From 2026.9 the identifier is ambiguous; the row id is not."""

    with patch(
        "custom_components.miwifi.device_tracker._LINKS_BY_VIA_DEVICE_ID", True
    ):
        assert _via_device_info(_Row()) == {"via_device_id": "node_row_id"}


def test_an_older_core_is_given_the_identifier_tuple() -> None:
    """`via_device_id` is not a parameter there, so it would raise."""

    with patch(
        "custom_components.miwifi.device_tracker._LINKS_BY_VIA_DEVICE_ID", False
    ):
        assert _via_device_info(_Row()) == {"via_device": (DOMAIN, MAC)}


def test_a_node_we_could_not_resolve_sets_no_link_at_all() -> None:
    """A link to a device that does not exist is the 2025.12 breakage."""

    assert _via_device_info(None) == {}


def test_the_node_row_is_returned_when_it_already_exists() -> None:
    """No second registry write for a node every client already points at."""

    row = _Row()
    dev_reg = MagicMock()
    dev_reg.async_get_devices.return_value = [row]

    with patch(
        "custom_components.miwifi.device_tracker.dr.async_get", return_value=dev_reg
    ):
        assert _ensure_via_device_exists(MagicMock(), MAC) is row

    dev_reg.async_get_or_create.assert_not_called()


def test_a_blank_router_mac_resolves_to_nothing() -> None:
    """The tracker carries no parent until the graph names one."""

    dev_reg = MagicMock()
    dev_reg.async_get_devices.return_value = []

    with patch(
        "custom_components.miwifi.device_tracker.dr.async_get", return_value=dev_reg
    ):
        for empty in ("", None, "none", "null"):
            assert _ensure_via_device_exists(MagicMock(), empty) is None

    dev_reg.async_get_or_create.assert_not_called()
