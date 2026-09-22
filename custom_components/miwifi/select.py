"""Select component."""

from __future__ import annotations

from .logger import _LOGGER
from typing import Any, Final

from homeassistant.components.select import (
    ENTITY_ID_FORMAT,
    SelectEntity,
    SelectEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    ATTR_SELECT_REQUESTED_OPTION,
    ATTR_SELECT_SIGNAL_STRENGTH_OPTIONS,
    ATTR_SELECT_WIFI_2_4_CHANNEL,
    ATTR_SELECT_WIFI_2_4_CHANNEL_NAME,
    ATTR_SELECT_WIFI_2_4_CHANNEL_OPTIONS,
    ATTR_SELECT_WIFI_2_4_CHANNELS,
    ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH,
    ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH_NAME,
    ATTR_SELECT_WIFI_5_0_CHANNEL,
    ATTR_SELECT_WIFI_5_0_CHANNEL_NAME,
    ATTR_SELECT_WIFI_5_0_CHANNEL_OPTIONS,
    ATTR_SELECT_WIFI_5_0_CHANNELS,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL_NAME,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL_OPTIONS,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNELS,
    ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH,
    ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH_NAME,
    ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH,
    ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH_NAME,
    ATTR_STATE,
    ATTR_WIFI_2_4_DATA,
    ATTR_WIFI_5_0_DATA,
    ATTR_WIFI_5_0_GAME_DATA,
    ATTR_WIFI_ADAPTER_LENGTH,
)
from .entity import MiWifiEntity
from .enum import Wifi, DeviceClass
from .exceptions import LuciError
from .updater import LuciUpdater, async_get_updater

PARALLEL_UPDATES = 0

CHANNELS_MAP: Final = {
    ATTR_SELECT_WIFI_2_4_CHANNEL: ATTR_SELECT_WIFI_2_4_CHANNELS,
    ATTR_SELECT_WIFI_5_0_CHANNEL: ATTR_SELECT_WIFI_5_0_CHANNELS,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL: ATTR_SELECT_WIFI_5_0_GAME_CHANNELS,
}

DATA_MAP: Final = {
    ATTR_SELECT_WIFI_2_4_CHANNEL: ATTR_WIFI_2_4_DATA,
    ATTR_SELECT_WIFI_5_0_CHANNEL: ATTR_WIFI_5_0_DATA,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL: ATTR_WIFI_5_0_GAME_DATA,
    ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH: ATTR_WIFI_2_4_DATA,
    ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH: ATTR_WIFI_5_0_DATA,
    ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH: ATTR_WIFI_5_0_GAME_DATA,
}

OPTIONS_MAP: Final = {
    ATTR_SELECT_WIFI_2_4_CHANNEL: ATTR_SELECT_WIFI_2_4_CHANNEL_OPTIONS,
    ATTR_SELECT_WIFI_5_0_CHANNEL: ATTR_SELECT_WIFI_5_0_CHANNEL_OPTIONS,
    ATTR_SELECT_WIFI_5_0_GAME_CHANNEL: ATTR_SELECT_WIFI_5_0_GAME_CHANNEL_OPTIONS,
    ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH: ATTR_SELECT_SIGNAL_STRENGTH_OPTIONS,
    ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH: ATTR_SELECT_SIGNAL_STRENGTH_OPTIONS,
    ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH: ATTR_SELECT_SIGNAL_STRENGTH_OPTIONS,
}

ICONS: Final = {
    f"{ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH}_min": "mdi:wifi-strength-1",
    f"{ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH}_mid": "mdi:wifi-strength-2",
    f"{ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH}_max": "mdi:wifi-strength-4",
    f"{ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH}_min": "mdi:wifi-strength-1",
    f"{ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH}_mid": "mdi:wifi-strength-2",
    f"{ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH}_max": "mdi:wifi-strength-4",
    f"{ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH}_min": "mdi:wifi-strength-1",
    f"{ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH}_mid": "mdi:wifi-strength-2",
    f"{ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH}_max": "mdi:wifi-strength-4",
}

MIWIFI_SELECTS: tuple[SelectEntityDescription, ...] = (
    SelectEntityDescription(
        key=ATTR_SELECT_WIFI_2_4_CHANNEL,
        name=ATTR_SELECT_WIFI_2_4_CHANNEL_NAME,
        icon="mdi:format-list-numbered",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    SelectEntityDescription(
        key=ATTR_SELECT_WIFI_5_0_CHANNEL,
        name=ATTR_SELECT_WIFI_5_0_CHANNEL_NAME,
        icon="mdi:format-list-numbered",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    SelectEntityDescription(
        key=ATTR_SELECT_WIFI_5_0_GAME_CHANNEL,
        name=ATTR_SELECT_WIFI_5_0_GAME_CHANNEL_NAME,
        icon="mdi:format-list-numbered",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    SelectEntityDescription(
        key=ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH,
        name=ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH_NAME,
        icon=ICONS[f"{ATTR_SELECT_WIFI_2_4_SIGNAL_STRENGTH}_max"],
        device_class=DeviceClass.SIGNAL_STRENGTH,
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    SelectEntityDescription(
        key=ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH,
        name=ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH_NAME,
        icon=ICONS[f"{ATTR_SELECT_WIFI_5_0_SIGNAL_STRENGTH}_max"],
        device_class=DeviceClass.SIGNAL_STRENGTH,
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    SelectEntityDescription(
        key=ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH,
        name=ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH_NAME,
        icon=ICONS[f"{ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH}_max"],
        device_class=DeviceClass.SIGNAL_STRENGTH,
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
)




async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    updater: LuciUpdater = async_get_updater(hass, config_entry.entry_id)

    entities: list[MiWifiSelect] = [
        MiWifiSelect(
            f"{config_entry.entry_id}-{description.key}",
            description,
            updater,
        )
        for description in MIWIFI_SELECTS
        if description.key
        not in [
            ATTR_SELECT_WIFI_5_0_GAME_CHANNEL,
            ATTR_SELECT_WIFI_5_0_GAME_SIGNAL_STRENGTH,
        ]
        or updater.supports_game
    ]

    async_add_entities(entities)


class MiWifiSelect(MiWifiEntity, SelectEntity):
    def __init__(
        self,
        unique_id: str,
        description: SelectEntityDescription,
        updater: LuciUpdater,
    ) -> None:
        super().__init__(unique_id, description, updater, ENTITY_ID_FORMAT)

        self._attr_current_option = updater.data.get(description.key, None)

        self._base_options: list = []
        if description.key in CHANNELS_MAP:
            self._base_options = list(
                updater.data.get(CHANNELS_MAP[description.key], [])
            )

        if description.key in OPTIONS_MAP and len(self._base_options) == 0:
            if (
                updater.data.get(ATTR_WIFI_ADAPTER_LENGTH, 2) > 2
                and description.key == ATTR_SELECT_WIFI_5_0_CHANNEL
            ):
                self._base_options = [
                    option
                    for option in OPTIONS_MAP[description.key]
                    if option not in OPTIONS_MAP[ATTR_SELECT_WIFI_5_0_GAME_CHANNEL]
                ]
            else:
                self._base_options = list(OPTIONS_MAP[description.key])

        self._attr_options = self._options_with_current(self._attr_current_option)

        self._wifi_data: dict = {}
        if description.key in DATA_MAP:
            self._wifi_data = updater.data.get(DATA_MAP[description.key], {})

        # What we last asked the router for - kept for the life of the entity,
        # not for a window - whether the router has ever confirmed it, and what
        # it was last seen replaced with. See _check_requested_option.
        self._requested_option: str | None = None
        self._requested_confirmed: bool = False
        self._requested_mismatches: int = 0
        self._override_reported: str | None = None

        self._attr_available: bool = (
            updater.data.get(ATTR_STATE, False)
            and len(self._attr_options) > 0
            and self._channel_is_reported()
        )

    def _options_with_current(self, current: Any) -> list:
        """Keep the channel the router reports selectable.

        The option list comes from `avaliable_channels`, which the updater asks
        once, on the first update, and whose answer can be narrower than what
        the radio is actually on: the RA82 leaves offer 36-48 and are then
        parked on the main's channel by the mesh controller. Home Assistant
        renders a select whose current option is not among its options as
        `unknown`, so the picker went blank exactly when the channel was worth
        seeing - and stayed blank, because the list is never asked for again.

        Widening it here needs no extra request and no guess about why the two
        disagree. Channels only: signal strength is min/mid/max everywhere, and
        a fourth value there would be a bug rather than a discovery.

        :param current: Any: the value the router reports
        :return list: the options, with `current` in numeric place if it is new
        """

        if self.entity_description.key not in CHANNELS_MAP:
            return list(self._base_options)

        # Absent keys arrive as the False that `data.get` was given as default.
        if current is None or isinstance(current, bool):
            return list(self._base_options)

        option: str = str(current).strip()

        # "0" is how a firmware says "unset"; it is not a channel to offer.
        if option in ("", "0") or option in self._base_options:
            return list(self._base_options)

        options: list = self._base_options + [option]

        try:
            return sorted(options, key=int)
        except (TypeError, ValueError):  # pragma: no cover
            return options

    def _channel_is_reported(self) -> bool:
        """Does the router tell us which channel this band is on?

        Band steering was the first suspect - it is what takes the 5 GHz
        switches out of service in switch.py - but it is the wrong test here.
        Under the same merged network the RD28 pair answers with a real 5 GHz
        channel while the RA82 pair answers with nothing, so keying on the
        merge hid a working control on half the fleet, and with it the only
        per-node view of the channel: the panel's own wifi endpoint is
        main-only (`ws_api._pick_updater`), so it shows one router's numbers on
        every node's card.

        What is actually broken is a channel picker for a band whose channel
        the router will not state. That is the condition, and it needs no
        knowledge of why the router is quiet.

        Signal strength is not covered: it is reported everywhere, on both
        bands, merged or not.

        Availability only. Registration must not depend on this: the value
        changes, a registry default does not.

        :return bool: not a channel control, or one the router reports
        """

        if self.entity_description.key not in CHANNELS_MAP:
            return True

        channel = self._updater.data.get(self.entity_description.key)

        # "0" is how a firmware says "unset" where it says anything at all.
        return str(channel or "").strip() not in ("", "0")

    @property
    def icon(self) -> str | None:
        option = self._attr_current_option
        return ICONS.get(f"{self.entity_description.key}_{option}")

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Publish the value you asked for while the router is ignoring it.

        The warning goes to a log the people this happens to are not reading.
        Comparing what you set against what the entity now shows was a matter
        of holding two screenshots side by side; here it is next to the state.

        :return dict[str, Any] | None: nothing to say unless the two disagree
        """

        if self._requested_option is None or str(self._attr_current_option) == str(
            self._requested_option
        ):
            return None

        return {ATTR_SELECT_REQUESTED_OPTION: self._requested_option}

    def _handle_coordinator_update(self) -> None:
        current_option: str = self._updater.data.get(self.entity_description.key, False)

        wifi_data: dict = {}
        if self.entity_description.key in DATA_MAP:
            wifi_data = self._updater.data.get(
                DATA_MAP[self.entity_description.key], {}
            )

        options: list = self._options_with_current(current_option)

        is_available: bool = (
            self._updater.data.get(ATTR_STATE, False)
            and len(options) > 0
            and len(wifi_data) > 0
            and self._channel_is_reported()
        )

        self._check_requested_option(current_option)

        data_changed: list = [
            key
            for key, value in wifi_data.items()
            if key not in self._wifi_data or value != self._wifi_data[key]
        ]

        if (
            self._attr_current_option == current_option
            and self._attr_options == options
            and self._attr_available == is_available
            and not data_changed
        ):
            return

        self._attr_available = is_available
        self._attr_options = options
        self._attr_current_option = current_option
        self._wifi_data = wifi_data

        self.async_write_ha_state()

    async def _wifi_2_4_channel_change(self, option: str) -> None:
        await self._async_update_wifi_adapter({"wifiIndex": Wifi.ADAPTER_2_4.value, "channel": option})

    async def _wifi_5_0_channel_change(self, option: str) -> None:
        await self._async_update_wifi_adapter({"wifiIndex": Wifi.ADAPTER_5_0.value, "channel": option})

    async def _wifi_5_0_game_channel_change(self, option: str) -> None:
        await self._async_update_wifi_adapter({"wifiIndex": Wifi.ADAPTER_5_0_GAME.value, "channel": option})

    async def _wifi_2_4_signal_strength_change(self, option: str) -> None:
        await self._async_update_wifi_adapter({"wifiIndex": Wifi.ADAPTER_2_4.value, "txpwr": option})

    async def _wifi_5_0_signal_strength_change(self, option: str) -> None:
        await self._async_update_wifi_adapter({"wifiIndex": Wifi.ADAPTER_5_0.value, "txpwr": option})

    async def _wifi_5_0_game_signal_strength_change(self, option: str) -> None:
        await self._async_update_wifi_adapter({"wifiIndex": Wifi.ADAPTER_5_0_GAME.value, "txpwr": option})

    async def _async_update_wifi_adapter(self, data: dict) -> None:
        new_data: dict = self._wifi_data | data

        try:
            await self._updater.luci.set_wifi(new_data)
        except LuciError as _e:
            # This used to be swallowed at debug level while the entity went on
            # to show the new value anyway, so a router that refused the change
            # looked exactly like one that accepted it.
            _LOGGER.debug("WiFi update error: %r", _e)

            raise HomeAssistantError(
                f"{self._updater.ip} refused the change to"
                f" {self.entity_description.key}: {_e}"
            ) from _e

        self._wifi_data = new_data

    async def async_select_option(self, option: str) -> None:
        if action := getattr(self, f"_{self.entity_description.key}_change"):
            # Raises if the router refused it, and then nothing below runs.
            await action(option)

            self._requested_option = option
            self._requested_confirmed = False
            self._requested_mismatches = 0
            self._override_reported = None

            self._updater.data[self.entity_description.key] = option
            self._attr_current_option = option

            self.async_write_ha_state()

    def _check_requested_option(self, reported: Any) -> None:
        """Say so when the router replaces the value you chose.

        A mesh controller owns the radio settings of the nodes it manages: it
        answers `code: 0` and takes the value back later, and how much later is
        not bounded. On a four node mesh the RA82 leaves undo a channel or a
        power change on their own within minutes, while the RD28 leaf kept both
        for hours and lost them in one go the moment the main's profile was
        touched and pushed to every node. Accepted-then-replaced and
        accepted-and-kept are identical in the interface.

        3.6.12 watched for it with a counter that disarmed on the first refresh
        that agreed, which is blind to everything but an immediate revert: a
        controller that lets the change stand for a cycle and overwrites it
        later was invisible. So the request is remembered for the life of the
        entity instead, and any departure from it is reported - once per
        departure, because for a value the router will never give back, once per
        refresh would be a warning every thirty seconds for ever.

        Before the first confirmation two disagreeing refreshes are required: a
        poll already in flight when the write landed reports the old value once
        through no fault of the router.

        :param reported: Any: what this refresh says the value is
        """

        if self._requested_option is None:
            return

        # The key is simply absent while a node does not report the band, and
        # `data.get` hands that over as the False it was given as a default.
        if reported is None or isinstance(reported, bool):
            return

        if str(reported) == str(self._requested_option):
            self._requested_confirmed = True
            self._requested_mismatches = 0

            # Being overridden again later is a new event, and worth saying.
            self._override_reported = None
            return

        if not self._requested_confirmed:
            self._requested_mismatches += 1
            if self._requested_mismatches < 2:
                return

        if str(reported) == str(self._override_reported):
            return

        self._override_reported = str(reported)

        _LOGGER.warning(
            "[MiWiFi] %s replaced %s with %s after accepting %s."
            " Something on the router owns this setting: on a mesh the main's"
            " radio profile is pushed onto every node, so set it there rather"
            " than per node",
            self._updater.ip,
            self.entity_description.key,
            reported,
            self._requested_option,
        )