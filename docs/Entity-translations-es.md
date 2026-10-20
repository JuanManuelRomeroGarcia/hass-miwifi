# Traducciones de entidades de clientes

Disponible desde v3.13.0.

Los once sensores de cada cliente usan las traducciones de entidades de Home
Assistant en español, inglés, alemán, francés, portugués de Brasil, ruso, turco y
chino simplificado. Los estados de conexión, calidad de señal y bloqueo de acceso
a Internet también tienen traducción de presentación.

Por ejemplo, `Last activity` se presenta como «Última actividad», `Online` como
«Tiempo conectado», `no_signal` como «Sin señal» y el bloqueo `false` como
«Permitido». Home Assistant elige el idioma de presentación; no se fija al español.

Los entity_id, unique_id y nombres personalizados se conservan. HA exige claves
de traducción en minúsculas. En 3.13.0 cambian los estados de dos sensores:

| Estado anterior del sensor de conexión | Nuevo estado |
| --- | --- |
| `Lan` | `lan` |
| `2.4G` | `wifi_2_4` |
| `5G` | `wifi_5` |
| `Guest` | `guest` |
| `5G Game` | `wifi_5_game` |
| `IoT` | `iot` |

El sensor de bloqueo cambia `True`/`False` a `true`/`false`. Actualiza las
comparaciones de estado de estos dos sensores en plantillas y automatizaciones.
Usa los valores internos, no las etiquetas traducidas. Los atributos de conexión
y bloqueo del device_tracker, los estados de calidad como `no_signal` y la
duración del tiempo conectado no cambian.

Tras copiar la carpeta completa de la integración, reinicia HA y refresca la
interfaz para cargar los metadatos y traducciones. No hace falta borrar entidades
ni desactivar los sensores para regenerarlos.
