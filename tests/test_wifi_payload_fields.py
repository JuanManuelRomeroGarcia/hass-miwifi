"""Wi-Fi write snapshots use the same reported fields as the read path."""
import pytest

from custom_components.miwifi.updater import LuciUpdater


def test_nested_radio_fields_take_precedence_over_top_level_fallbacks():
    data = {"ssid": "test", "channelInfo": {"channel": 36, "bandwidth": "80"},
            "channel": "149", "bandwidth": "40"}
    assert LuciUpdater._prepare_wifi_data(data) == {
        "ssid": "test", "channel": 36, "bandwidth": "80"}


@pytest.mark.parametrize("channel_info", [None, {}, "invalid"])
def test_provider_fields_survive_missing_or_malformed_channel_info(channel_info):
    assert LuciUpdater._prepare_wifi_data({
        "channelInfo": channel_info, "channel": "149", "bandwidth": "80"}) == {
        "channel": "149", "bandwidth": "80"}
