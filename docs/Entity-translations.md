# Client entity translations

Available from v3.13.0.

All eleven client sensor names use Home Assistant entity translations in English,
Spanish, German, French, Brazilian Portuguese, Russian, Turkish and Simplified
Chinese. Connection, signal-quality and Internet-block states have translated
presentation too, selected by Home Assistant rather than hard-coded to Spanish.

Entity IDs, unique IDs and custom names are preserved. HA requires lowercase
translation keys, so two client sensors use canonical states in v3.13.0:

| Previous connection sensor state | New state |
| --- | --- |
| `Lan` | `lan` |
| `2.4G` | `wifi_2_4` |
| `5G` | `wifi_5` |
| `Guest` | `guest` |
| `5G Game` | `wifi_5_game` |
| `IoT` | `iot` |

The Internet-block sensor changes `True`/`False` to `true`/`false`. Update state
comparisons in automations/templates for these two sensors. Use canonical values,
not translated labels. Device-tracker connection/boolean attributes and
signal-quality values such as `no_signal` remain unchanged, as does connected
duration storage. Restart HA and refresh the interface; do not recreate entities.
