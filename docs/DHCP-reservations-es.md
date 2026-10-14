# Reservas DHCP (pruebas locales)

El panel **DHCP** permite consultar las reservas del router principal y, en los firmwares verificados, añadirlas, editar su IP o nombre y eliminarlas. Está disponible para administradores de Home Assistant. Cuando hay un solo principal, muestra su nombre e IP y carga sus reservas automáticamente, sin desplegable. Solo usa entradas cargadas con el rol `is_main` confirmado. Los nodos mesh quedan excluidos; el backend también rechaza consultas y escrituras dirigidas a ellos. Si hay varias redes independientes con sus propios principales, se muestra el selector para elegir la red correspondiente.

## Compatibilidad inicial

Se han comprobado las API nativas de BE10000 / RC01 con firmware **1.1.56**: consulta, alta incremental, cambio de IP y nombre para una misma MAC, y eliminación. Las escrituras quedan habilitadas únicamente en ese perfil y cuando DHCP está activado. Los demás firmwares muestran las reservas en modo de solo lectura si sus respuestas son compatibles. AX1800 con firmware 3.0.34 (#314) está pendiente de confirmar sus formatos y comportamiento.

El panel no modifica la dirección LAN, el rango DHCP, DNS ni la duración de las concesiones. Consulta DHCP bajo demanda, sin añadir llamadas a cada ciclo de actualización de los clientes mesh.

## Uso

1. Abre MiWiFi → DHCP: el router principal y sus reservas se cargan automáticamente. Se muestra su nombre e IP sin desplegable. Solo si hay varios principales de redes independientes se solicita elegir uno.
2. Revisa las reservas actuales. Elige un cliente conocido o introduce manualmente MAC, IPv4 y nombre.
3. Guarda. Se valida la dirección de host dentro de la subred, se excluyen la IP del router, la dirección de red y la de difusión, y se rechazan conflictos con otras reservas o clientes conocidos por el router.
4. Para editar, pulsa **Editar reserva**. La MAC no cambia: si necesitas otra MAC, añade su reserva por separado.
5. Para quitar una reserva, pulsa **Eliminar reserva** y confirma el registro mostrado.

Cada escritura consulta primero la configuración actual, rechaza un formulario desactualizado, envía una sola reserva y comprueba el resultado y las reservas ajenas. No sobrescribe toda la lista. La comparación reduce conflictos, pero la API del router no ofrece una operación atómica frente a cambios simultáneos desde la app Xiaomi u otra sesión.

Si aparece un error al escribir, puede que el router haya aplicado el cambio antes de perderse la respuesta. **Actualiza la lista y comprueba el resultado antes de repetirlo.** El panel bloquea nuevas escrituras hasta esa lectura; no hay reintentos ni restauraciones automáticas que sobrescriban cambios externos.

## MAC privadas y concesiones

Una reserva vincula una IP a una MAC concreta. Si el móvil cambia su MAC privada, la reserva anterior no se traslada automáticamente. Las reglas de sustitución automática de MAC de MiWiFi limpian los dispositivos de Home Assistant; no cambian reservas DHCP del router. Para una IP estable, mantén una MAC estable para esa red o gestiona su nueva reserva expresamente.

Guardar una reserva no obliga al cliente a renovar su concesión actual. Puede necesitar reconectarse o renovar DHCP. No reinicies todos los nodos para esta prueba.

## Prueba conjunta con #346

Esta carpeta local combina v3.9.1, la adaptación preparada del #346 y DHCP; no es una nueva versión publicada.

1. Haz una copia de la carpeta instalada `custom_components/miwifi` y sustituye su contenido por la carpeta local completa de la integración. No copies `.git`, `tests`, `tools` ni credenciales.
2. Reinicia Home Assistant y recarga el panel sin caché (Ctrl+F5).
3. Comprueba los roles principal/mesh y los contadores durante varios ciclos; recarga una entrada y comprueba que se mantienen. Revisa los registros.
4. En DHCP, confirma que la lista coincide con la interfaz del router. Usa una reserva de prueba acordada y una IP libre, conserva las reservas existentes y comprueba alta, edición y eliminación desde ambas interfaces.
5. Si pruebas un cliente real, comprueba la IP tras renovar su concesión. Comprueba que no se recrean clientes antiguos purgados ni se alteran las reglas de MAC privadas.
6. Elimina la reserva temporal y vuelve a comprobar registros, topología y contadores. Conserva un diagnóstico si algo falla.

Las pruebas automatizadas verifican comportamiento y compatibilidad de HA con dobles de la API. La adquisición de concesiones por clientes reales y la persistencia tras reiniciar el router requieren pruebas reales.

Para previsualizar la vista sin HA ni acceso al router: ejecuta `python tools/preview_dhcp.py` y abre `http://127.0.0.1:8766`. Solo utiliza datos ficticios. En WSL, ejecuta las pruebas legacy con `TZ=UTC`, como en CI, para mantener coherente el reloj simulado de las pruebas.
