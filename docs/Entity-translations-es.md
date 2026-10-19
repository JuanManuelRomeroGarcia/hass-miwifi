# Traducciones de entidades de clientes

Preparado localmente para la próxima actualización; sin publicar.

Los once sensores de cada cliente usan las traducciones de entidades de Home
Assistant en español, inglés, alemán, francés, portugués de Brasil, ruso, turco y
chino simplificado. Los estados de conexión, calidad de señal y bloqueo de acceso
a Internet también tienen traducción de presentación.

Por ejemplo, `Last activity` se presenta como «Última actividad», `Online` como
«Tiempo conectado», `no_signal` como «Sin señal» y el bloqueo `False` como
«Permitido». Home Assistant elige el idioma de presentación; no se fija al español.

Los entity_id y unique_id se conservan. Los estados internos usados en
plantillas/automatizaciones siguen siendo `5G Game`, `no_signal`, `True` o `False`;
no hay que sustituirlos por las traducciones visibles. No se cambia la duración
almacenada por el sensor de tiempo conectado. Se conservan los nombres que el
usuario haya personalizado en HA.

Tras copiar la carpeta completa de la integración, reinicia HA y refresca la
interfaz para cargar los metadatos y traducciones. No hace falta borrar entidades
ni desactivar los sensores para regenerarlos. La comprobación visual en tu HA
queda pendiente de esa copia.
