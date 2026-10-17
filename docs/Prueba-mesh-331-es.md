# Prueba local conjunta — #331, #362, #359 y #326

Preparación: 17 de octubre de 2026. Rama local:
`prueba-mesh-331-diagnostico`, en `F:\Miwifi_HA\hass-miwifi`.
Combina el #331 (`37554ae`), nuestro #362 (`7eb4368`), el #359 (`40ecd31`)
y el #326 (`c63dca9`). Los commits de los autores se conservan.
Este documento conserva el procedimiento de prueba sobre la base 3.11.0.
Los cambios se incorporan en la versión 3.12.0; no es necesario cambiar de rama
para instalar esa versión estable.

## Validación automática y criterio de trabajo

La combinación anterior de #331 + #362 pasó las baterías locales: 456 pruebas en HA
2026.10.0 y 455 en HA 2026.9.3, con una omisión prevista. También pasaron las
regresiones independientes, las comprobaciones del panel y el empaquetado.
La batería legacy de esta combinación se detuvo por decisión del mantenedor;
no se cuenta como un resultado completado. Estos resultados no se atribuyen a
la combinación ampliada de cuatro PR. El #331 por separado ya tenía sus
205 pruebas legacy verificadas y sus checks de GitHub en verde.

A petición del mantenedor, las baterías completas se ejecutan mediante la CI
del PR en GitHub, sin duplicarlas sistemáticamente en local. Solo se repiten
pruebas locales concretas cuando hay un fallo o una corrección que lo justifique.

La combinación ampliada pasó 54 pruebas concretas de opciones globales, modo AP,
ciclos de actualización y entidades WAN en HA 2026.10.0. Incluyen una regresión
nueva que confirma que guardar el modo AP de un nodo mantiene la selección global
de sensores y solo recarga esa entrada. La validación completa de los cuatro PR
se reserva para la CI cuando se suba la integración de estos cambios.

## Qué debe hacer y qué no

Un nodo mesh puede haber quedado registrado también como cliente Wi-Fi/LAN.
El #331 deja de contarlo como cliente y retira sus entidades de cliente MiWiFi
cuando un censo lo identifica positivamente con `isap > 0`. La identificación
queda pendiente hasta poder efectuar la limpieza, incluso si el siguiente censo
ya no incluye esa fila o devuelve `isap=0`.

Una coincidencia solo por IP no autoriza borrar entidades. Los clientes normales,
las entidades del router y las de otras integraciones deben conservarse. Las
reservas DHCP y las reglas NAT tampoco deben cambiar.

Los identificadores de las entidades eliminadas no se migran a las del router:
si una automatización utilizaba el tracker duplicado, hay que revisar esa referencia.
Esta prueba comprueba el comportamiento; no evita la limpieza automática prevista.

## 1. Antes de copiar los archivos

1. Crea una **copia completa de seguridad de HA**, comprueba que ha terminado y
   guárdala fuera de HA. Incluye configuración, registros de entidades/dispositivos
   y la integración. Una copia solo de `custom_components/miwifi` no permite
   recuperar registros borrados ni sus personalizaciones.
2. Descarga los diagnósticos de las entradas MiWiFi actuales y conserva un volcado
   ampliado anonimizado de referencia.
3. Anota los nombres y los ID de las entidades de cada router: disponibilidad,
   tiempo activo, WAN y contadores. Comprueba sus áreas/nombres personalizados.
   Anota también la MAC propia y, si existe, la MAC de enlace mesh del nodo.
4. Si existe una fila duplicada del nodo como cliente, guarda sus ID de entidades
   y comprueba qué automatizaciones, personas o paneles la utilizan. Solo ese
   cliente duplicado es candidato al borrado previsto. El dispositivo router
   legítimo debe conservarse.
5. Elige dos o tres clientes normales como controles: uno conectado al principal,
   otro al nodo y, si tienes uno, un cliente desconectado. Anota sus ID y
   personalizaciones. Anota también una entidad de otra integración si comparte
   el mismo aparato o la misma MAC.

No fabriques duplicados ni modifiques `.storage` para forzar la prueba. No cambies
las MAC privadas ni las reglas de sustitución durante ella, y no ejecutes purgas
manuales. Anota si coincide con una autopurga programada para distinguir sus efectos.

## 2. Instalación por SFTP

Copia el contenido completo de:

`F:\Miwifi_HA\hass-miwifi\custom_components\miwifi\`

a:

`/config/custom_components/miwifi/`

Reinicia HA. No elimines ni vuelvas a crear las entradas MiWiFi. Abre el panel
evitando la caché. No necesitas copiar `tests`, `tools` ni esta documentación a HA.

## 3. Arranque y limpieza diferida

Espera al menos **tres actualizaciones completas** con el principal y el nodo
disponibles; el tiempo depende de tu intervalo de consulta. La limpieza no se
ejecuta en la primera actualización del coordinador.

Comprueba después de esas actualizaciones:

- Las entradas y entidades legítimas del principal y del nodo siguen existiendo,
  conservan los mismos ID y personalizaciones y actualizan sus datos.
- Los clientes de control conservan sus ID, nombres/áreas y referencias. Un
  cliente desconectado puede seguir fuera o no disponible; no debe desaparecer
  por esta limpieza de nodos.
- Si había un nodo duplicado como cliente y se recibió identificación positiva,
  desaparecen sus entidades de cliente (tracker/sensores), incluidas las
  deshabilitadas. Su fila solo puede desaparecer si queda vacía y pertenece
  exclusivamente a MiWiFi. No se debe borrar el router legítimo.
- Las entidades de otras integraciones se conservan, aunque utilicen la misma
  MAC. Una fila compartida vacía no debe perder la propiedad de otra integración.
- Los contadores dejan de incluir el propio nodo como cliente y mantienen los
  clientes reales; no tienen por qué coincidir con los valores anteriores si
  antes se contaba el nodo. Los contadores agregados del firmware pueden diferir.
- En un cliente conectado al nodo, «Conectado a través de» sigue apuntando al
  router correcto. Si había una colisión con una MAC de enlace, deja pasar otra
  actualización tras la limpieza para comprobar que se registra el alias.

Si no había duplicados o el router no ofrece una identificación positiva, la
ausencia de borrados es correcta, pero **no valida en hardware la ruta de borrado**.
No borres nada manualmente para hacer que la prueba parezca pasar.

## 4. Ajustes globales y locales (#359)

Después de comprobar primero la limpieza con el modo AP apagado:

1. Abre las opciones de MiWiFi desde **Ajustes → Dispositivos y servicios** de HA.
   En el principal deben aparecer «Ajustes globales de la malla» y «Ajustes de este
   dispositivo». En el nodo debe estar disponible el apartado local. Si HA no
   identifica ningún principal, los globales también pueden ofrecerse en los nodos.
2. Entra en los globales y anota panel, nivel de log, autopurga y sensores de
   clientes. **No cambies la opción de sensores de clientes para esta prueba.**
   Apagarla voluntariamente puede eliminar sus registros de sensores y perder
   personalizaciones; eso es diferente de eliminar un nodo duplicado como cliente.
3. Guarda los globales sin alterar los valores. Comprueba que los sensores y los
   trackers de los clientes de control siguen existiendo y actualizándose.
4. Abre los ajustes locales de un nodo. Deben incluir IP, acceso, seguimiento,
   intervalos y la opción AP; no deben incluir autopurga ni la selección global
   de sensores. Si «Carga forzada» ya estaba activada, debe seguir visible.
5. Guarda los ajustes locales sin cambios. No debe cambiar la configuración de
   los demás nodos ni activar o desactivar sensores de clientes. El nodo guardado
   puede recargarse; las otras entradas deben seguir funcionando.

## 5. Modo AP manual (#326)

No actives esta opción en el router que proporciona la puerta de enlace/DHCP.
Primero confirma que todo funciona con ella **apagada**, que es el valor por defecto.

Si decides probarla, hazlo **solo en un nodo secundario**:

1. Anota su modo, clientes, contadores y entidades de velocidad antes de cambiarlo.
2. Activa «Punto de acceso / nodo mesh» en sus ajustes locales y guarda. Espera
   tres actualizaciones completas. Los clientes deben seguir presentes y los
   contadores deben seguir actualizándose; el nodo no debe pasar a contarse como
   un cliente del principal.
3. Las entidades de velocidad WAN obtenidas de `misystem/status`, cuando ese
   nodo proporciona esos contadores, deben conservar sus ID y actualizarse.
   Al omitir `wan_info`, el estado/enlace WAN puede ser **desconocido**, en vez de
   «desconectado»; no es un fallo por sí solo. No se esperan datos WAN del nodo
   cuando su firmware no los proporciona.
4. Comprueba que el principal sigue funcionando y conserva su WAN, DHCP y clientes.
5. Desactiva la opción del nodo, guarda y confirma que recupera la detección normal
   sin duplicar entidades ni perder los sensores de los clientes.

El volcado API ampliado usa su propio catálogo de lecturas: puede consultar rutas
que el ciclo normal del modo AP omite. Un error de `mode` dentro del ZIP no prueba
que se haya ignorado la opción durante la actualización normal.

## 6. Persistencia y uso normal

1. Recarga la entrada del nodo desde HA, espera tres actualizaciones y repite las
   comprobaciones de conservación. Comprueba después la recarga del principal.
2. Reinicia HA una segunda vez. Los duplicados retirados no deben reaparecer;
   los routers y los clientes normales deben conservarse y actualizarse.
3. Desconecta y vuelve a conectar solo el Wi-Fi de un cliente de control, sin
   cambiar su MAC. Debe seguir usando sus entidades y recuperar su presencia.
4. Revisa que las reservas DHCP y reglas NAT permanecen iguales, y que siguen
   funcionando las vistas del panel, los avisos en español y el volcado ampliado.

Una instalación con mesh por cable no valida el caso inalámbrico del #334.

## 7. Qué guardar y cuándo parar

Descarga al terminar los diagnósticos de cada entrada, el ZIP de logs y un nuevo
volcado ampliado con anonimización activada. Apunta qué duplicado desapareció,
qué ID se conservaron y si ocurrió al arrancar, recargar o reiniciar. Revisa los
archivos antes de publicarlos: los logs y diagnósticos ordinarios pueden contener
información privada.

**Detén la prueba si desaparece un router legítimo, un cliente normal o una entidad
de otra integración**, o si se recrean con ID nuevos. Guarda los archivos y el
momento del fallo; no ejecutes más purgas ni reinstales la integración. Para
recuperar registros eliminados, restaura la copia completa anterior de HA;
restaurar solo los archivos de código no deshace esos borrados.
