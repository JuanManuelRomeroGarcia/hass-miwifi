# Diagnósticos y soporte mesh

> Disponibilidad: **v3.9.0 y posteriores** para la captura `mesh_support` descrita aquí.

## Descargar el diagnóstico de Home Assistant

Abre **Ajustes → Dispositivos y servicios → MiWiFi**, entra en el menú de una entrada configurada y selecciona **Descargar diagnósticos**. Espera actualizaciones correctas y descarga el archivo justo después de reproducir el problema. No necesitas reinstalar, restablecer el router ni borrar entradas de la integración.

El archivo incluye el diagnóstico habitual de la entrada y una sección `mesh_support` que cubre **todos los nodos MiWiFi cargados**. Una entrada que no está cargada no puede aportar observaciones en directo. El volcado de datos del router es otro archivo, con respuestas originales; no sustituye esta captura.

## Qué contiene `mesh_support`

- Versiones de HA e integración, modelos y firmware, y opciones numéricas o booleanas efectivas.
- Topología, pertenencia anonimizada de clientes, relaciones con sus nodos padres y marcas de clientes movidos.
- Observaciones recientes de las respuestas existentes de `misystem/devicelist` y `wifi_connect_devices`, conservando los indicadores de actividad.
- Contadores antes de reiniciar, después de recibir clientes del padre, tras otras fuentes y al terminar cada actualización.
- Eventos iniciales y primer censo de cada fuente, junto a un historial reciente limitado a 60 eventos y 12 censos por entrada. Hasta 512 clientes por censo, con indicadores explícitos si se recorta.

La captura vive en memoria y no hace peticiones extra. Recargar una entrada reinicia su historial; reiniciar HA borra el historial y cambia los alias anonimizados. Los alias MAC/IP/entrada son coherentes entre todos los nodos y descargas durante la misma ejecución de HA. Tras reiniciar, reproduce el problema y descarga de nuevo.

## Compartir un informe útil

**Comparte públicamente solo `mesh_support`.** Excluye nombres, SSID, credenciales y respuestas arbitrarias completas. Las secciones anteriores de datos, dispositivos y peticiones conservan información habitual de la red; no se anonimiza todo el archivo.

Indica la hora del problema, los contadores esperados y mostrados, si afecta a entidades de HA o solo al panel, y las opciones de rol, carga forzada, rastreo y sensores de clientes por nodo. Explica si comienza al arrancar, actualizar, recargar, cambiar de nodo o renombrar un aparato.

Para sustitución de MAC privadas, describe también los alias de nombres configurados y si hay exactamente una MAC conectada. Las reglas no se exportan en `mesh_support`. No publiques nombres identificativos ni volcados completos innecesariamente. Si hacen falta respuestas originales, sustituye cada MAC de forma coherente en todos los archivos y referencias al padre; no uses el mismo marcador para todos los aparatos.

## Límites al interpretar los datos

Un padre sin correspondencia, un indicador de espacios en una IP o la ausencia de IP activa son pistas, no la explicación completa por sí solos. Una descarga a mitad de actualización puede contener un contador transitorio; compara los eventos de actualización terminada. Que funcione en una instalación no resuelve automáticamente un informe de otro modelo o firmware sin su verificación.

Consulta también la guía de [MAC privadas](Random-MAC-addresses-es.md).
