# MAC privadas y sustitución automática

> Disponibilidad: **v3.9.0 y posteriores**. Las versiones anteriores no incluyen la sustitución automática de MAC privadas.

## Por qué aparecen varias fichas del mismo móvil o reloj

Un aparato puede usar una MAC privada distinta para cada red Wi-Fi o cambiar esa dirección posteriormente. MiWiFi identifica los clientes por su MAC; la dirección anterior puede dejar una ficha inactiva junto al aparato conectado. Pasar de un nodo mesh a otro con **la misma MAC** es un caso distinto y no implica una identidad nueva.

Dos clientes con el mismo nombre no son necesariamente el mismo aparato. La sustitución está **desactivada por defecto** y solo se aplica a los nombres y alias únicos que asocies explícitamente. No cambia la privacidad Wi-Fi del aparato, las reservas DHCP ni combina automáticamente todos los dispositivos con el mismo nombre.

## Configurarlo en el panel

1. Entra con una cuenta de administrador de Home Assistant.
2. Abre **MiWiFi → Ajustes → Opciones de integración → Sustitución automática de MAC**, en los ajustes del nodo principal. Las reglas abarcan todas las entradas MiWiFi cargadas, no solo ese router.
3. Selecciona **Añadir un cliente conocido** o **Añadir manualmente**. Los nombres ya incluidos en una regla no se ofrecen de nuevo.
4. Despliega la fila del aparato. Introduce un **nombre del router o de la app Xiaomi** por línea, incluidos los anteriores. Las mayúsculas no importan y se ignoran los espacios al principio y al final. Cambiar solo el nombre visible en Home Assistant no crea un alias del router.
5. Pulsa **Guardar**. Añadir, editar o quitar una fila no tiene efecto hasta guardar. Un cambio de reglas no necesita recargar la integración ni reiniciar HA.
6. Conecta el aparato actual al Wi-Fi y espera las actualizaciones de los nodos. El nombre actual y los anteriores deben estar **en una sola regla**, no en reglas separadas.

Ejemplo de un mismo reloj renombrado en el router:

```text
Reloj JuanMa
SM-L315F
```

Utilízalo únicamente si ambos nombres corresponden al mismo reloj físico y son únicos en tu red. Si tienes dos aparatos del mismo modelo, ponles nombres distintos en el router antes de configurar la sustitución.

## Cuándo se elimina la MAC anterior

Todos los nodos MiWiFi cargados deben aportar listas de clientes completas, recientes y obtenidas correctamente. Debe existir **exactamente una MAC asociada conectada**. Las MAC anteriores deben estar ausentes de esas listas o explícitamente inactivas. Si una MAC tiene indicadores de actividad desconocidos o inválidos, se protege. Los datos caducan tras tres intervalos de actualización más un tiempo de espera de ese nodo, con un mínimo de 60 segundos.

Al guardar una regla se buscan MAC anteriores en los datos actuales, las cachés guardadas por nodo y los registros de dispositivos/rastreadores MiWiFi de HA. Esto incluye clientes históricos que solo conservan una ficha no disponible en HA. Se comparan nombres proporcionados por la integración, no nombres de visualización personalizados por el usuario.

Se eliminan los **rastreadores y sensores de cliente MiWiFi** de la MAC anterior, incluidos los desactivados, en todos los nodos cargados y sus cachés. La ficha del dispositivo solo se elimina si no quedan entidades ajenas y tiene una única entrada propietaria. La MAC conectada actual permanece. Esta sustitución verificada no espera el número de días de la purga normal.

**No se transfieren identificadores de entidades o dispositivos, áreas, nombres personalizados, asignaciones a personas ni referencias de automatizaciones a la MAC actual.** Revisa las automatizaciones, paneles y personas que usaban el rastreador eliminado. El historial no se migra ni se borra expresamente con esta acción; se conserva según la retención habitual de Home Assistant.

## Renombrado, reinicios y desactivación

- Si el router informa de un nombre nuevo en una MAC conocida y conectada, puede aprenderse como alias. Si cambian a la vez el nombre y la MAC, incluye explícitamente los dos nombres en la misma regla: el nombre nuevo por sí solo no demuestra la identidad.
- Las reglas, las MAC aprendidas y la supresión de direcciones retiradas se conservan tras recargar o reiniciar HA. Los registros antiguos, guardados o desconectados del router no deben recrear la dirección retirada.
- Una MAC retirada puede volver si datos recientes del router confirman una **conexión real**. La supresión no es una lista negra permanente.
- Pulsa **Quitar regla** y después **Guardar** para detener futuras sustituciones de ese aparato. Quita todas las reglas y guarda para desactivar la función. No se restauran las entidades ya eliminadas; la supresión continúa hasta una reconexión real.
- La purga normal sigue siendo útil para clientes sin una identidad configurada. Simula antes de aplicar; la selección de MAC y la antigüedad siguen gobernando esa acción.

## Si queda un duplicado

| Qué ocurre | Qué comprobar |
| --- | --- |
| El rastreador actual aparece fuera o desconectado | Conecta el aparato y espera datos recientes de los nodos. |
| Cambió de nombre | Despliega la regla y guarda ambos nombres, uno por línea. |
| El antiguo solo tiene una ficha no disponible en HA | Modifica y guarda otra vez la regla para incorporar su registro. |
| Hay dos MAC asociadas conectadas | La sustitución espera deliberadamente. Comprueba que no sean dos aparatos físicos. |
| Un nodo no se actualiza o devuelve datos incompletos | Recupera primero sus actualizaciones correctas; no borres entradas HA como solución. |
| Quedan entidades de otra integración | Su ficha se conserva; solo se eliminan las entidades de cliente MiWiFi. |
| Los cambios desaparecen al salir | Guarda antes de cambiar de página. |

Si sigue fallando, indica las versiones, modelos y firmware, los alias configurados y si cada nodo se actualiza. Descarga el diagnóstico después de reproducir el problema. Comparte públicamente **solo `mesh_support`** para estudiar contadores y conexiones mesh: anonimiza identificadores MAC, IP y entradas de todos los nodos cargados. No contiene nombres de clientes ni reglas de sustitución. Las otras secciones pueden contener datos privados habituales de dispositivos o de red; no publiques el JSON entero sin revisarlo.

## Acción YAML

El panel es la opción recomendada. Un administrador también puede ejecutar:

```yaml
action: miwifi.configure_mac_replacement
data:
  clients:
    watch:
      - Reloj JuanMa
      - SM-L315F
    phone:
      - Redmi-Note-14-Pro-5G
```

`clients` sustituye **todas las reglas guardadas**: incluye cada aparato que quieras conservar. Las claves `watch` y `phone` identifican las reglas; no son nombres del router. `clients: {}` desactiva todas las reglas. El panel carga la configuración completa antes de editar e impide guardar si falla esa carga.

## Validación realizada

Las pruebas locales cubren alias, fichas históricas que solo quedan en el registro, datos recientes de todos los nodos, MAC simultáneas conectadas, actividad desconocida, persistencia, eliminación entre nodos y protección de entidades ajenas. En una instalación real de HA se confirmó la eliminación de una MAC anterior de un Redmi y la ficha antigua no disponible de un reloj renombrado. El mantenedor confirmó el funcionamiento correcto tras el último reinicio completo de HA. Esto no demuestra un comportamiento idéntico en todos los modelos y firmware.
