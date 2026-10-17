# Ajustes de la malla y del dispositivo (v3.12.0)

En Home Assistant, abre Configurar en la entrada MiWiFi.

- **Ajustes globales de la malla**: panel, nivel de registro, programación de autopurga y sensores de clientes. Se ofrecen en el principal; si todavía no se reconoce ninguno, se pueden abrir desde cualquier entrada. El último guardado explícito decide el ajuste compartido de sensores. Hasta ese momento se conserva el comportamiento anterior.
- **Ajustes de este dispositivo**: conexión, contraseña, intervalos, rastreo, unidades WAN, sondeo de puertos, modo AP y carga forzada. Guardar aquí conserva los ajustes globales y normalmente recarga solo esa entrada. Cambiar el estado compartido de sensores recarga todas las entradas.

Desactivar los sensores de clientes los elimina de todas las entradas. Conserva una copia de seguridad antes de hacerlo si has personalizado sus entidades.

## Opción de punto de acceso / nodo mesh

Está desactivada por defecto. Actívala cuando el aparato está detrás de otra puerta de enlace y necesitas omitir las consultas de modo, WAN y filtros MAC que su firmware no admite en ese papel. También puede corresponder al principal de una malla que funciona como AP detrás del router de otro fabricante. No la actives en tu puerta de enlace para ocultar un fallo WAN.

La opción cambia el comportamiento de la integración; no configura el router ni cambia Wi-Fi, DHCP o NAT. El modo será `access_point`, se mantienen el rastreo y los contadores de clientes y las velocidades que reporte `misystem/status`. Estado, enlace, dirección y tipo WAN pueden quedar desconocidos al omitir esas consultas. No se inventan valores WAN2.

## Limpieza de nodos confundidos con clientes

Los nodos conocidos no se registran ni restauran como clientes. Solo una identificación positiva del firmware (`isap > 0`) autoriza limpiar sus antiguas entidades de cliente, incluso deshabilitadas y de otras entradas MiWiFi. Una coincidencia por IP no autoriza borrarlas. Las entidades del router y de otras integraciones se conservan.

Si una automatización usaba el antiguo tracker de cliente del nodo, revisa esa referencia: no se migra automáticamente. No borres manualmente una fila sin entidades si otros dispositivos la usan como padre.

Las pruebas físicas de esta versión cubren mallas por cable. Si detectas duplicados o un satélite inalámbrico tratado como cliente, abre un nuevo issue con modelo, firmware, versión HA, pasos y diagnóstico anonimizado.
