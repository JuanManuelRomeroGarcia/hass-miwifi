# Volcado ampliado de consultas API

Disponible desde v3.12.0. Primera prueba real
en HA 2026.10.1 completada el 16 de octubre de 2026: principal RC01 y nodo RC06,
sin errores comunicados en el registro de HA. El archivo conserva tres fallos
de consulta (NAT en el principal y modo en el nodo), sin impedir el resto de la
captura. La segunda prueba, el 17 de octubre, confirmó los avisos en español y la
anonimización adicional en el archivo. También se verificaron los enlaces de
apoyo del panel y su presentación discreta. Rama: `diagnostico-api-router`.

En **MiWiFi → Ajustes → Volcar datos del enrutador**, marca **Consultas API y
respuestas nuevas (principal y nodos)** y genera el archivo. La opción está
desmarcada por defecto. Con ella se incluyen todos los bloques del catálogo y
los routers cargados; las casillas de bloques individuales dejan de aplicarse.
También se puede abrir este diagnóstico cuando el panel no reconoce un principal.

Se realizan consultas nuevas, no una copia del historial. Cada router aparece con
su modelo, firmware, rol, dirección y contadores guardados, claramente separados
de las respuestas nuevas. El JSON incluye ruta API sin autenticación, parámetros,
hora, duración, respuesta y resultado. Los errores del firmware conservan su
respuesta JSON; los fallos de transporte pueden no tener respuesta. Se indican
las consultas omitidas por modelo, rol, desactivación de WAN2 o límites de captura.

El catálogo contiene sistema, modos, topología, WAN1, Wi-Fi, clientes, filtros MAC,
NAT, QoS, DHCP, VPN, comprobación de versión, permisos de actualización y lectura
del LED. Añade WAN2/puertos para RD08 cuando corresponde, canales de hasta cuatro
adaptadores y lecturas móviles conocidas para CB0401. No es un descubrimiento de
todas las API posibles del firmware: lo no verificado se omite o queda fuera del
catálogo. Que una ruta responda con error no significa que no exista en otro modelo.

La preparación local posterior a 3.13.0 amplía las lecturas verificadas RC01/RC06:
mapa de puertos, control térmico RC01, preferencias mesh, steering RC06,
configuración Multi-WAN y WPS/NFC, con omisiones explícitas por modelo y rol.
No alimenta nuevos sensores ni cambia el sondeo habitual. Las unidades térmicas
y el significado de `wpa3_only` requieren la interpretación descrita en la
[guía de muestras API](Router-API-live-es.md).

Solo se usa un catálogo fijo de lecturas: no hay reinicios, cambios de Wi-Fi,
reservas DHCP, reglas NAT ni actualizaciones de firmware. Tampoco se llama a los
métodos de configuración Wi-Fi con parámetros vacíos para intentar leerlos.
Se reutiliza la sesión del cliente de la integración; su recuperación normal de
autenticación puede seguir actuando si el router devuelve un token caducado.

## Límites y privacidad

- Hasta 4 segundos por consulta, 45 por router y 120 por captura, con un máximo de
  32 routers. Un fallo no impide incluir el resto. Cancelar la tarea cancela la
  petición activa. No se permiten dos volcados simultáneos.
- Respuestas exportadas de hasta 1 MB por consulta y 8 MB por captura. Se conserva
  un indicador si una respuesta se omite por tamaño; no se exporta texto no JSON.
  Estos límites se aplican a la retención/exportación, no al tamaño recibido por HTTP.
- Contraseñas, claves y tokens conocidos siempre se ocultan, incluso al desmarcar
  **Anonimizar IP/MAC y nombres**. Al marcarla también se sustituyen identificadores
  por valores distintos y coherentes dentro del archivo: no todas las MAC quedan
  iguales, y se mantienen las relaciones entre clientes, padres y nodos. Los alias
  IP no conservan las subredes ni el alcance de las direcciones originales.
- Los alias y sus mapas no se guardan para futuras capturas ni se incluyen en el
  archivo. Revisa el resultado antes de compartirlo: pueden existir campos nuevos
  específicos de un firmware que aún no estén identificados como sensibles.
- El ZIP se conserva en la exportación privada de HA y se descarga como
  administrador con un enlace firmado. No se envía a GitHub ni a servicios externos.
  El volcado anterior se elimina después de crear correctamente el nuevo.

## Prueba manual

Conserva una copia de la integración, copia `custom_components/miwifi` completa por
SFTP y reinicia HA. Refresca el panel evitando su caché. Genera un ZIP ampliado,
comprueba principal y nodos, errores y omisiones, y verifica que no aparecen
contraseñas ni tokens. Compara con el volcado por bloques y confirma que las redes,
reservas, reglas y actualización normal de clientes no han cambiado.
Esta prueba no publica una versión nueva.
