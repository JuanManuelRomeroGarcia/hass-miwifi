# Comprobar compatibilidad de un router Xiaomi

Español | [English](Router-API-community.md)

Estas herramientas son voluntarias, se ejecutan desde el PC y no necesitan HA.
Conserva una copia completa del repositorio: el script HTTP utiliza el catálogo
y el anonimizador de la integración. Necesitas Python 3.11 o posterior. SSH es
opcional y debe estar habilitado previamente; los scripts no lo desbloquean.

Descarga el [ZIP de la rama de pruebas `api-live-trial`](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/archive/refs/heads/api-live-trial.zip)
y extráelo. Abre una terminal dentro de la carpeta extraída para ejecutar los
comandos siguientes. No copies la integración de esta rama a HA para estas
pruebas: basta con ejecutar las herramientas desde el PC. La versión estable
publicada no contiene todavía estas opciones nuevas.

## Opción sencilla: consultas HTTP

Desde la carpeta del repositorio, sustituye la IP del ejemplo por la del router:

```powershell
python tools/router_api_live.py --host 192.0.2.1 --sha256-host 192.0.2.1 --probe-model-specific --output .cache/informe-router
```

Pide la contraseña de administración web, sin mostrarla. `--sha256-host` debe
coincidir con el algoritmo del router: SHA-256 en nuestro BE10000; nuestro
BE7000 usa SHA-1 y no lleva esa opción. No es una regla universal por modelo.
Si no lo conoces, consulta la configuración existente de MiWiFi; no pruebes
contraseñas diferentes. Para un nodo añade `--mesh-node 192.0.2.1`.

Toma tres muestras, con diez segundos entre rondas. El catálogo es limitado:
no pretende probar todas las API del firmware. La opción de modelos nuevos
permite comprobar rutas de funciones como el ventilador, sin crear sensores
ni asumir sus unidades en modelos diferentes. Una omisión por rol o por falta
de MAC no equivale a una API inexistente.

## Opción avanzada: descubrir las rutas por SSH y consultar por HTTP

En Windows instala también PuTTY/Plink. Entra previamente por SSH y verifica la
huella del router; la herramienta no acepta claves desconocidas automáticamente.

```powershell
python tools/router_api_inventory.py --host 192.0.2.1 --password --probe-http --sha256-host 192.0.2.1 --probe-model-specific --output .cache/informe-router
```

Pide dos contraseñas independientes: SSH y administración web. El usuario SSH
predeterminado es `root`; cámbialo con `--user USUARIO` si corresponde. No hay
contraseñas fijas en los scripts. En Linux/macOS se puede usar OpenSSH con una
clave o agente, sin `--password`; consulta la guía de inventario.

El inventario busca declaraciones sin ejecutar sus manejadores. La fase HTTP
solo consulta una lista fija revisada: una ruta descubierta no se convierte
automáticamente en una petición. Sin `--probe-http` se generan igualmente los
dos JSON, pero el de respuestas indica explícitamente que no se consultaron.

## Qué compartir

Comparte únicamente estos dos archivos de la carpeta elegida:

- **`routes.json`**: rutas, identificación del modelo/firmware y alcance del plan
  o del inventario. Sin respuestas HTTP.
- **`responses.json`**: respuestas HTTP anonimizadas, errores y omisiones; con
  SSH también enumera las declaraciones que no se consultaron.

Indica si el equipo es principal, punto de acceso o nodo mesh. El indicador
`main_or_standalone` de la herramienta HTTP no distingue automáticamente AP:
conviene aportar ese contexto. Usa una carpeta por router si ejecutas pruebas
por separado, porque los archivos se reemplazan.

Los informes HTTP eliminan credenciales y seudonimizan identificadores conocidos;
revísalos antes de publicarlos porque otros firmwares pueden introducir campos
que aún no conocemos. Los archivos locales `IP.json`, listados de SSH y
`comparacion.md` del inventario pueden contener información de la red: no hacen
falta para colaborar. No compartas archivos de contraseñas.

Una respuesta correcta, una lista vacía, una ruta no disponible y un error de
autenticación son resultados distintos. Utilizaremos modelo, firmware, rol y
validación de los campos para decidir qué funciones habilitar en MiWiFi.

## Texto breve para anunciar la prueba

> Buscamos usuarios de distintos routers Xiaomi para mejorar la compatibilidad
> de MiWiFi con Home Assistant. Hemos preparado una herramienta voluntaria que
> consulta información del router desde el PC, sin cambiar sus ajustes.
>
> La prueba básica solo necesita acceso web al router; SSH es opcional para
> descubrir las rutas que declara cada firmware. Cada usuario introduce sus
> propias credenciales y estas no se incluyen en los informes.
>
> Comparte `routes.json` y `responses.json`, revisados antes de publicarlos, e
> indica el modelo, firmware y si funciona como principal, AP o nodo mesh.
> Buscamos comprobar qué funciones ofrece cada equipo, por ejemplo temperatura,
> ventilador, puertos y métricas Wi-Fi. Una función ausente o una lista vacía
> también es información útil.
>
> Sigue esta guía y utiliza la versión del repositorio que contenga ambos
> scripts y estas opciones. No es necesario instalar una versión de prueba en HA.

Para publicar el anuncio, enlaza esta guía desde la rama o versión que incluya
los cambios. No indiques que las opciones nuevas están en v3.13.0: se han
preparado después de esa publicación. No adjuntes las capturas privadas usadas
por el mantenedor para verificar las herramientas.
