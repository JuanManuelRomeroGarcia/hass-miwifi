# Comprobar lecturas de API con varias muestras

`tools/router_api_live.py` complementa el [inventario por SSH](Inventario-APIs-SSH-es.md).
El inventario encuentra declaraciones del firmware; esta herramienta consulta
un catálogo fijo de lecturas revisadas y toma unas pocas muestras por HTTP.
Requiere Python 3.11 o posterior y no necesita instalar Home Assistant ni librerías.

No recorre automáticamente las rutas descubiertas por SSH. No acepta rutas
arbitrarias, escribe ajustes, activa diagnósticos ni añade sondeos permanentes a HA.
La autenticación normal sí crea una sesión de administración del router.

## Uso

Ejemplo con direcciones de documentación, para sustituir por las reales:

```powershell
python tools/router_api_live.py --host 192.0.2.1 --host 192.0.2.2 --sha256-host 192.0.2.1 --mesh-node 192.0.2.2
```

Pide la contraseña de **administración web del router**, no la de SSH. Se usa la
misma en ambos hosts; si difiere, ejecútalos por separado. El algoritmo de los
hosts no indicados en `--sha256-host` es SHA-1. Debe coincidir con el configurado
en MiWiFi; no se prueban algoritmos o contraseñas alternativos tras un rechazo.

Por defecto toma tres muestras y espera diez segundos entre rondas. Son capturas
puntuales, no una monitorización. Consulta por separado cada router y cada ruta.
Usa `--scheme https` si tu router lo admite con un certificado de confianza;
no se desactiva su validación ni se siguen redirecciones de las peticiones.
Tampoco se utiliza un proxy del entorno.

Para limitar las consultas:

```powershell
python tools/router_api_live.py --host 192.0.2.1 --sha256-host 192.0.2.1 --query client_details --query thermal_control --samples 3 --interval 10
```

La asociación de un cliente requiere una MAC real elegida por el usuario:

```powershell
python tools/router_api_live.py --host 192.0.2.1 --sha256-host 192.0.2.1 --query client_association --client-mac 02:00:00:00:00:41
```

La MAC del ejemplo es ficticia: sustitúyela por un cliente de tu red. No se
inventan clientes para obtener resultados. Esa consulta se hace al principal.

## Informes y límites

Se generan en `.cache/router-api-live/`, ignorado por Git:

- `samples.json`: muestras completas con secretos eliminados e identificadores
  seudonimizados, resultado, fecha y duración de cada lectura.
- `routes.json`: plan de rutas HTTP, parámetros anonimizados y motivos de omisión.
- `responses.json`: resultados y respuestas anonimizadas; mismo contenido que
  `samples.json`, conservado por compatibilidad. No incluye credenciales.
- `comparacion.md`: resultados por consulta y si su respuesta cambió entre muestras.

`--output RUTA` cambia el destino. Una ejecución posterior reemplaza ambos
informes; usa otra carpeta para conservar la captura anterior. Contraseñas y
tokens nunca se incluyen en las salidas. Con `--password-file` el archivo de
entrada lo gestiona el usuario; la herramienta no lo elimina. No lo publiques.

Límites: cuatro routers, hasta seis muestras, pausa entre 5 y 60 segundos,
presupuesto global de 180 segundos por defecto (máximo 600), cuatro segundos
por operación de red, respuesta de 256 KiB y captura de respuestas de 8 MB.
El tiempo de una ronda se añade a la pausa: no es una frecuencia exacta.
Los fallos, listas vacías y lecturas omitidas se guardan explícitamente.
Incluso si falla el inicio de sesión se guarda el plan de rutas y `login_failed`;
ese fallo no se interpreta como función no disponible.
No se reintenta la autenticación; un fallo de permisos o tres fallos de
transporte consecutivos detienen las lecturas de ese router. Un error HTTP
no es una prueba de que esa función sea inexistente en todos sus modos.

## Qué podemos interpretar

| Consulta | Uso y límites |
| --- | --- |
| `client_details` | RSSI, protocolo y enlaces TX/RX. El principal puede centralizar clientes mesh. Tasas PHY y tráfico son magnitudes distintas. |
| `thermal_control` | RC01 1.1.56: máximo de siete entradas térmicas en °C; velocidad en RPM medidas o estimadas por PWM. Cero no prueba parada. [Detalles](RC01-thermal-control-es.md). |
| `port_map` | Capacidades y servicios asignados, no velocidad negociada. Verificado en RC01/RC06 y catálogo previo RD08. |
| `mesh_backhaul_preference` | Preferencia configurada, no tipo de enlace actual. |
| `mesh_steering` | Ajustes de steering RC06; no una medición de roaming. |
| `multiwan_basic` | Configuración de Multi-WAN, no caudal; no se activa WAN2. |
| `wps_info`, `nfc_info` | `wpa3_only` se calcula desde el campo `encryption`; no demuestra SAE/PMF por cada radio. |
| `client_association` | Banda/nodo asociados y vínculo fijado, distinguiendo ambos conceptos. |

Las lecturas específicas se limitan a los modelos ya verificados. Un firmware
nuevo requiere revisar su código y respuesta, no solo encontrar su ruta en el
inventario. Una respuesta cambiante no garantiza la frescura de todos sus campos;
contrástala con un cambio conocido y con la app del router.

Para investigar otro modelo se puede añadir `--probe-model-specific`. Consulta
también las rutas específicas del catálogo fijo aunque el modelo no esté
verificado. El informe conserva `model_unverified_routes`: una respuesta correcta
no demuestra que sus campos o unidades sean iguales. Esta opción solo afecta a
esta prueba voluntaria, no cambia las restricciones de HA. Las reglas de rol
mesh/principal y los límites siguen activos.

Si cada router tiene una contraseña web distinta, añade `--per-host-password`;
la pide por separado para cada host. No se combina con `--password-file`.

Para colaborar con un informe sigue la [guía de compatibilidad](Router-API-community-es.md).

## Volcado desde HA

La preparación local posterior a 3.13.0 añade al bloque de diagnóstico API las
lecturas verificadas de control térmico, mapa de puertos, preferencias mesh,
steering, Multi-WAN, WPS/NFC y estado WAN, con filtros por modelo y rol.
No añade sensores ni cambia el sondeo normal. Las consultas dirigidas a una MAC
se mantienen en la herramienta, fuera del volcado general.

Tras copiar `custom_components/miwifi/` y reiniciar HA, abre **MiWiFi → Ajustes →
Volcar datos del router**, activa el diagnóstico API y descarga el ZIP. Conserva
la anonimización de identificadores. Los routers no compatibles mostrarán un
motivo de omisión; no se reemplazan datos ausentes con ceros.
