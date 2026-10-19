# Prueba local: contadores, restauración, arranque y autopurga

Rama: `prueba-mesh-autopurga`. Base: v3.12.0 (`99fd335`). No publicada.
La integración y el panel siguen mostrando 3.12.0 durante esta prueba.

Se integran los PR #364, #366, #368 y #370 de brembygit con sus commits originales.
Se añaden dos correcciones locales: reserva del programador antes de su tarea
asíncrona (evita temporizadores duplicados) y captura de errores LuCI al leer NAT.
Las lecturas NAT fallidas conservan la última captura válida y reintentan tras un
minuto, sin enviar escrituras al router. No se cambia la jerarquía global de errores.

## Antes de copiar

1. En Configurar MiWiFi → Ajustes globales de la malla, anota el intervalo/hora
   actuales y guarda **Autopurga cada X días = 0**. Comprueba que queda guardado.
   El calendario corregido puede ejecutar una limpieza vencida al arrancar;
   mantén la autopurga desactivada hasta revisar expresamente los candidatos.
2. Haz una copia de seguridad de HA que incluya registros y almacenamiento de
   MiWiFi, y conserva la carpeta actual. Restaurar solo código no recupera
   entidades que se hayan eliminado.
3. Copia por SFTP `custom_components/miwifi/` del proyecto a
   `/config/custom_components/miwifi/`. No copies `.storage`, `.git`, adjuntos,
   pruebas ni configuraciones del PC. Reinicia HA y espera a que carguen las entradas.

## Pruebas, una por una

### 1. Arranque normal

Comprueba principal y nodo disponibles, clientes conocidos y contadores. El nodo
mesh debe tener el rol correcto desde el arranque si su topología lo identifica.
No cambies el modo AP ni la carga forzada para arreglar un síntoma sin anotarlo.
No deben aparecer IDs duplicados ni `Task exception was never retrieved` de NAT.
Si falla una conexión NAT puede quedar un aviso controlado y una captura anterior;
no equivale a una actualización correcta de NAT ni a un cambio de reglas reales.

### 2. Restauración de presencia

Mantén un cliente conectado y otro ausente, anota sus estados y reinicia de forma
normal. En el primer reinicio tras actualizar puede faltar el estado guardado de
la versión anterior. Repite un segundo reinicio limpio para validar la restauración:
el conectado no debería tener una salida/entrada falsa y el ausente debe seguir
fuera. No deberían anunciarse como nuevos clientes ya conocidos.

Esta restauración de clientes propios se amplía a nodos con carga forzada; si no
la usamos, no demos ese caso por probado físicamente. La prueba automática sí lo
cubre. Un cliente antes conectado pero ahora ausente puede conservar `home` durante
la espera inicial: hasta 5 minutos más `stay_online`. No implica que el router lo
haya observado. Si llegó mientras HA estaba apagado, espera a una lectura real.

### 3. Último cliente de un nodo

No desconectes todos los aparatos de casa. Si hay un nodo/banda que permita aislar
un único cliente de prueba sin afectar servicios, conecta ese cliente, espera a
que se cuente y desconéctalo o muévelo al principal. Tras un censo completo del
principal, sus contadores anteriores deben dejar de quedar atascados. La topología
puede dar un total diferente de la suma por bandas: no proporciona ese desglose.
Si no podemos vaciar el nodo con seguridad, dejamos ese caso físico pendiente.

### 4. Autopurga: primero simulación

Mantén el calendario en 0. En Herramientas de desarrollador → Acciones, ejecuta:

```yaml
action: miwifi.purge_inactive_devices
data:
  days: 7
  only_randomized: true
  include_orphans: true
  include_orphans_without_age: false
  verbose: true
  apply: false
```

`days` debe coincidir con el intervalo que realmente quieras usar. No actives
`apply`: la simulación permite revisar candidatos sin borrarlos. No rebajes la
antigüedad ni actives la inclusión sin fecha para forzar resultados.

Después revisaremos juntos el resultado antes de reactivar el calendario. La
retención de fecha, el arranque vencido, los cambios de horario, los fallos, la
cancelación y la reserva de un único programador están cubiertos por las pruebas
automáticas; no hace falta provocar una purga real en casa para comprobarlos.

### 5. Evidencia y vuelta atrás

Si aparece un fallo, guarda hora, acción y registro; descarga diagnóstico mesh y,
si necesitamos respuestas, el volcado API anonimizado. No publiques credenciales
ni el archivo completo sin revisarlo. Para volver al código estable, restaura la
carpeta anterior y reinicia; deja la autopurga en 0 hasta resolver el problema.

## Validación local

98 pruebas enfocadas aprobadas en HA 2026.10.0: programación/cancelación,
recuperación NAT, contadores de nodos, restauración de clientes/estados y rol en
el primer refresco. No se han repetido las baterías completas ni subido el conjunto
a GitHub. La prueba en HA real continúa pendiente.
