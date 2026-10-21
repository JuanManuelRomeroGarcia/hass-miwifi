# Inventario de APIs por router mediante SSH

`tools/router_api_inventory.py` es una herramienta independiente para investigar
firmwares Xiaomi. No necesita Home Assistant ni instala nada en el router.
No se incorpora al sondeo normal de MiWiFi ni requiere mantener SSH abierto
para usar la integración.

## Qué hace

- Lee modelo, firmware y arquitectura del archivo de versión.
- Recorre los controladores LuCI existentes en ese router. Utiliza su propio
  `luac -p -l -l`, que analiza sin ejecutar el código ni generar `luac.out`.
  Reconoce tanto los listados habituales como el bytecode Fate/Z de Xiaomi.
  Si no hay `luac`, intenta analizar los controladores que estén en texto.
- Obtiene rutas declaradas, nombres de manejadores e indicios de parámetros.
- Clasifica rutas como candidatas de lectura, acciones/cambios o pendientes
  de revisión. No llama a los manejadores ni prueba automáticamente URLs.
- Consulta solo la presencia de los objetos ubus `trafficd` y `mitempctrl`;
  no ejecuta sus métodos. Un fallo de ubus se distingue de un objeto no listado.
- Guarda SHA-256 de los controladores cuando está disponible `sha256sum`.
- Produce un JSON por router y una comparación en Markdown.

No reinicia servicios, no escribe configuración, no cambia el firmware ni
descarga/ejecuta herramientas en el router. El límite es de 64 controladores,
64 MiB de salida aceptada y 120 segundos por router por defecto; una lectura
truncada o un error no se presentan como inventario completo.

## Uso en Windows

Necesita Python 3.10 o posterior y PuTTY/Plink. Se probó con Plink 0.85,
que permite `-pwfile`.

Ejemplo con direcciones de documentación, para sustituir por las reales:

```powershell
python tools/router_api_inventory.py --host 192.0.2.1 --host 192.0.2.2 --password
```

Pide la contraseña sin mostrarla. Para varios hosts en una ejecución se usa
la misma contraseña. Si son diferentes, ejecuta la herramienta por separado.
El usuario predeterminado es `root`; se puede cambiar con `--user` y el puerto
con `--port`.

Plink debe conocer la clave del servidor. Si no está guardada, la conexión se
detiene y muestra su huella; no se acepta automáticamente. Verifica esa huella
mediante tu acceso de confianza. Después puedes fijarla con
`--host-key "IP=SHA256:HUELLA"`, una opción por cada IP que lo necesite.
La huella no es la contraseña ni la clave privada.

La contraseña pedida se entrega a Plink en un archivo temporal privado que se
elimina al terminar, incluso cuando falla SSH. No se incluye en los argumentos
del proceso Plink, los JSON ni la comparación. Un cierre forzado del proceso o
del equipo puede impedir la limpieza; no uses `--password-file` con un archivo
que vayas a publicar o versionar. Con esa opción, el archivo lo gestiona quien
invoca el script y la herramienta no lo borra.

## Uso con claves SSH

Linux/macOS usan OpenSSH por defecto, con una clave/agente ya configurado y el
servidor ya verificado en `known_hosts`:

```sh
python3 tools/router_api_inventory.py --host 192.0.2.1 --identity ~/.ssh/id_ed25519
```

Se puede elegir `--backend ssh` o `--backend plink`. Las claves privadas de
Plink deben estar en su formato PPK. La contraseña interactiva y las huellas
pasadas con `--host-key` solo se admiten con Plink; OpenSSH utiliza su gestión
normal de claves y confianza, sin desactivarla.

## Resultados

Por defecto se guardan en `.cache/router-api-inventory/`, ignorado por Git:

- `IP.json`: datos del firmware y declaraciones de API.
- `routes.json`: declaraciones por router con alias, modelo y firmware, sin IP
  de conexión ni cadenas internas del código. Es el inventario para compartir.
- `responses.json`: resultados HTTP; sin `--probe-http` marca las rutas como
  `not_queried`, porque SSH no ejecuta los manejadores HTTP.
- `comparacion.md`: resumen y rutas diferentes entre los routers inspeccionados.

`--output RUTA` cambia el destino. Se reemplazan los informes de las IP
inspeccionadas; guarda una copia si quieres conservar un inventario anterior.
`--save-raw` añade los listados originales para investigar problemas del
analizador. Estos informes contienen IP, modelo y funciones del firmware;
los listados pueden incluir constantes internas. Revísalos antes de compartirlos.

### Inventario y comprobación HTTP en una ejecución

Requiere Python 3.11+ y conservar el repositorio completo. Añade `--probe-http`:

```powershell
python tools/router_api_inventory.py --host 192.0.2.1 --password --probe-http --sha256-host 192.0.2.1 --probe-model-specific --output .cache/informe-router
```

Pide primero la contraseña SSH y luego la contraseña de administración web;
pueden ser distintas. `--sha256-host` se usa solo cuando el acceso web requiere
SHA-256; los demás hosts usan SHA-1. No se prueban algoritmos alternativos al
fallar. Para contraseñas diferentes entre routers, ejecuta una vez por router con
carpetas de salida diferentes. Marca los nodos con `--mesh-node IP`.

Solo se ejecuta el catálogo fijo de `router_api_live.py`, nunca todas las rutas
descubiertas. `--probe-model-specific` permite comprobar ese catálogo en modelos
todavía no verificados, sin cambiar las reglas de rol mesh/principal. Se guardan
los resultados HTTP en `http/` y se incorporan al `responses.json` principal;
las demás rutas siguen en `not_queried_routes`. Un error o una lista vacía no
confirman ausencia de la función. [Guía para colaboradores](Router-API-community-es.md).

## Cómo usar el inventario para decidir qué consultar

Hay que distinguir tres niveles:

1. **Declarada**: el controlador contiene una entrada. Puede estar protegida
   por una condición de modelo o una función desactivada.
2. **Lectura revisada**: hemos comprobado su implementación, parámetros,
   dependencias y posibles efectos. Un getter también puede iniciar trabajo
   o devolver credenciales. La clasificación del script no sustituye esa revisión.
3. **Comprobada en ejecución**: la API responde en ese firmware y modo de red,
   con campos, unidades y valores válidos. Solo entonces debe alimentar sensores.

El script deja `runtime_verified=false` y `read_safety_verified=false` en todas
las rutas. No crea listas de permiso automáticas. `symbol_hints` son cadenas
del código, no un esquema confirmado de respuesta.

El analizador no descubre todos los casos de registro dinámico ni las API de
servicios binarios, y sus indicios no son un análisis completo de llamadas.
Dos routers que declaran una misma ruta pueden devolver esquemas distintos.

En HA, la selección final debe combinar modelo/firmware, modo principal/AP,
respuesta real y validación de cada campo, con respaldo y espera antes de
reintentar rutas no disponibles. No se debe convertir un campo ausente en cero
ni crear un sensor de ventilador solo porque el firmware declare la función.

## Comprobación local realizada

Se ejecutó por SSH contra RC01/BE10000 1.1.56 y RC06/BE7000 1.1.38:
13 controladores en cada uno, 610 y 614 rutas declaradas respectivamente,
606 comunes y sin errores de desensamblado. La comparación privada incluye
los nombres de las diferencias. No se ejecutó ninguna de esas acciones.

Pruebas unitarias específicas, sin HA ni conexión al router:

```sh
python -B tests/test_router_api_inventory.py
```
