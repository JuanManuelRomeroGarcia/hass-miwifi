"""Which config entries a device row belongs to, on every supported core.

Core 2026.10 reports every read of `DeviceEntry.config_entries` on a plain row
and drops it in 2027.10; the single `config_entry_id` replaces it. Older cores
still need `config_entries`: before 2026.8 it is the only field, and a row can
belong to several entries.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miwifi.const import DOMAIN
from custom_components.miwifi.helper import device_config_entry_ids

_REPORT: str = "_report_deprecated_config_entries_property"


class _Core2610Row:
    """A plain row on core 2026.10: reading `config_entries` is reported."""

    is_composite_device: bool = False
    config_entry_id: str = "entry_a"

    @property
    def config_entries(self) -> set[str]:
        raise AssertionError("read the deprecated DeviceEntry.config_entries")


def test_core_2026_10_reads_the_single_entry() -> None:
    assert device_config_entry_ids(_Core2610Row()) == {"entry_a"}


def test_a_composite_row_keeps_every_entry() -> None:
    """A composite still spans several entries; reading it there is not reported."""

    row = SimpleNamespace(
        is_composite_device=True,
        config_entry_id="entry_a",
        config_entries={"entry_a", "entry_b"},
    )

    assert device_config_entry_ids(row) == {"entry_a", "entry_b"}


def test_cores_before_2026_10_read_config_entries_as_before() -> None:
    """2026.8 and 2026.9 have `config_entry_id` but report nothing either way."""

    row = SimpleNamespace(config_entry_id="entry_a", config_entries={"entry_a"})

    assert device_config_entry_ids(row) == {"entry_a"}


def test_cores_before_2026_8_keep_a_row_with_several_entries() -> None:
    row = SimpleNamespace(config_entries={"entry_a", "entry_b"})

    assert device_config_entry_ids(row) == {"entry_a", "entry_b"}


def test_the_result_is_a_copy() -> None:
    """Callers combine it with set operators; the row must not change."""

    entries = {"entry_a"}
    row = SimpleNamespace(config_entries=entries)

    device_config_entry_ids(row).add("entry_b")

    assert entries == {"entry_a"}


@pytest.mark.skipif(
    not hasattr(dr, _REPORT), reason="this core does not report config_entries"
)
async def test_a_real_registry_row_is_read_without_a_report(
    hass: HomeAssistant,
) -> None:
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={(DOMAIN, "00:00:00:00:00:01")}
    )

    with patch.object(dr, _REPORT) as report:
        entries = device_config_entry_ids(device)
        assert not report.called

        # The control: the plain read is what the core reports.
        assert device.config_entries == entries
        assert report.called

    assert entries == {entry.entry_id}
