# Identidad de los nodos mesh y filtros de las tarjetas

Disponible en instalaciones desde código que incorporen el PR #354; no está
incluido en la versión publicada v3.10.0.

Algunos nodos tienen dos MAC: la de su dispositivo y la que utiliza el router
principal en el campo `parent` de un cliente. Pueden ser distintas en un RA82 y
podrían explicar el problema de la tabla del AX6S del issue #329. Ese caso
concreto todavía necesita confirmación.

Los trackers y sensores de clientes exponen estos atributos:

| Atributo | Significado |
| --- | --- |
| `router_mac` / `connected_via_router_mac` | MAC del padre que comunica el mesh. Conservan su comportamiento anterior. |
| `connected_via_router_device_mac` | MAC propia del dispositivo del nodo que atiende al cliente. |
| `connected_via_router_name` | Nombre personalizado del dispositivo en Home Assistant; si no existe, nombre del router. |
| `connected_via_entry_id` | Entrada de integración que atiende al cliente. |

En Herramientas para desarrolladores → Estados, abre un cliente conectado al
nodo afectado. Si la tabla filtra por la MAC propia del nodo, utiliza
`connected_via_router_device_mac` y copia su valor exacto, respetando las
mayúsculas. También puedes filtrar por `connected_via_entry_id`. Si mantienes
`router_mac`, necesitas la MAC del padre que aparece en el cliente. La
integración no modifica automáticamente el YAML de tus tarjetas. Conviene
filtrar por MAC o por entrada: el nombre visible puede cambiar o repetirse.

Espera a que el principal y el nodo estén cargados y completen una actualización.
Los atributos nuevos pueden estar vacíos hasta conocer el nodo que atiende al
cliente. El alias también permite que «Conectado a través de» apunte al nodo
correcto. Si otra fila ya ocupa el alias, no se fusiona ni elimina ese dispositivo;
la resolución puede utilizar el coordinador cargado. La limpieza de registros
antiguos de nodos que aparecían como clientes se trata por separado en el #331.
