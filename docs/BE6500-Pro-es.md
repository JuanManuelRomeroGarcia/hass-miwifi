# Compatibilidad BE6500 Pro / RD08 (PR #358)

Estos cambios están en revisión y no están incluidos en v3.10.0.
Se basan en las respuestas del RD08 con firmware 1.1.96 aportadas en
[#355](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/355) y
[#356](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/issues/356).
Falta confirmar la integración modificada en el router real.

## Conexiones de clientes

El RD08 devuelve LAN=1, 2,4 GHz=2, 5 GHz=3, invitados=7 e IoT=9 en
`misystem/devicelist`. La interpretación se aplica solo al RD08, también
cuando envía sus clientes a otro nodo mesh. Los demás modelos conservan sus
códigos actuales. Los códigos sin verificar siguen siendo desconocidos.

## Doble WAN (solo lectura)

En un RD08 que actúa como router principal se consulta
`misystem/get_ps_service?service=multiwan`. Si está activado, se lee
`xqnetwork/wan_info?wan_name=WAN2`. La detección se guarda durante cinco
minutos, incluidos los fallos; WAN2 se actualiza en los sondeos normales.
Cada petición tiene un límite de seis segundos. Estas consultas adicionales
no se realizan en otros modelos ni en los nodos mesh.

Los identificadores y las lecturas actuales de WAN1 se conservan.
El nuevo sensor **WAN2 IP address** tiene los atributos `enabled`, `type`,
`link` y `connected`. El panel de estado muestra WAN2 por separado cuando
está activado, con etiquetas en los ocho idiomas disponibles. Si WAN2 está
desconectado, no se conserva su concesión anterior como IP actual. Si la
consulta falla o está incompleta, sus datos quedan no disponibles, sin
marcar WAN1 como desconectado. Activar o desactivar la doble WAN puede tardar
hasta cinco minutos en reflejarse.

No se modifica la política WAN ni la configuración de puertos. El ancho de
banda configurado y los pesos no son velocidades medidas: no se inventan
sensores de tráfico de WAN2 ni se deduce el comportamiento de conmutación o
balanceo a partir del modo numérico. Antes de fusionar hay que comprobar en
el router real los estados activado, desconectado, desactivado y reconectado,
además de WAN1 y la actualización de clientes mesh.

## Memoria

En el diagnóstico aportado, `misystem/status.mem.total` devuelve 256 MB.
Se muestra ese valor del firmware, sin sustituirlo por una suposición basada
en el modelo. Para mostrar otra capacidad hace falta una respuesta verificada.

Antes de compartir pruebas, elimina contraseñas, tokens de sesión y datos de
tu red privada. No publiques direcciones del navegador que contengan `stok`.
