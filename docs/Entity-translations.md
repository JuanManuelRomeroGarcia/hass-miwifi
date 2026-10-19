# Client entity translations

Prepared locally for the next update; not released yet.

All eleven client sensor names use Home Assistant entity translations in English,
Spanish, German, French, Brazilian Portuguese, Russian, Turkish and Simplified
Chinese. Connection, signal-quality and Internet-block states have translated
presentation too, selected by Home Assistant rather than hard-coded to Spanish.

Entity IDs, unique IDs and custom names are preserved. Serialized states used by
automations remain `5G Game`, `no_signal`, `True` and `False`; do not replace those
values with their displayed translations in templates. Connected duration storage
is unchanged. Update the complete integration folder, restart HA and refresh the
interface; do not delete or recreate entities to update their translations.
