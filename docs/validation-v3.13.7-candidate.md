# MiWiFi 3.13.7b1 — protocolo de prueba voluntaria

Esta candidata privada combina los PR #399 y #398. No es una release estable ni se distribuye mediante HACS. El ZIP contiene `custom_components/miwifi`; comprobar su SHA-256 antes de usarlo. No ejecutar cambios en la red de invitados sin autorización expresa del propietario.

## Entorno y recuperación

1. Preferir una instancia de Home Assistant aislada de la instalación estable con una copia restaurada de su configuración. Evitar dos instalaciones que envíen acciones o automatizaciones al mismo router y desactivar automatizaciones de prueba que realicen escrituras. Tomar una copia completa verificable de HA antes de empezar.
2. Guardar aparte una copia exacta de `config/custom_components/miwifi` que contiene el parche local de @carpshark. Conservar también una copia privada de `config/.storage/miwifi/` y de los registros de dispositivos y entidades incluidos en el respaldo completo. Pueden contener datos personales o credenciales: no subirlos ni compartirlos.
3. En la instancia de prueba, parar HA, sustituir solamente la copia de `custom_components/miwifi` por el directorio del ZIP y reiniciar. No aplicar simultáneamente el parche local encima de la candidata: se prueba el código completo del ZIP. No eliminar la integración, dispositivos ni entidades. Anotar versión de HA, modelos y firmware sin divulgar IP, MAC, nombres privados ni contraseñas.
4. Para volver atrás, parar HA de prueba, sustituir la carpeta de MiWiFi por la copia exacta con su parche y reiniciar. Si es necesario recuperar el estado anterior de registros o almacenamiento, restaurar la copia completa por el procedimiento habitual de HA; hacerlo en frío y considerar que se perderán cambios posteriores al respaldo. Verificar nombres, entidades y conectividad. No borrar el parche ni su copia hasta verificar la recuperación.

## Medición antes y después

- Usar el mismo intervalo, número de nodos y clientes, ciclo de actualización y secuencia de desplazamiento para la instalación original parcheada y la candidata. Anotar comienzo, fin, reinicios y cambios manuales.
- En Herramientas de desarrollo → Eventos, escuchar `device_registry_updated` y `entity_registry_updated` **por separado** durante cada intervalo. Contar eventos de tipo `update` de los dispositivos y entidades MiWiFi elegidos; distinguir las altas iniciales y los cambios manuales de las actualizaciones repetidas. La vista solo recoge eventos mientras escucha; no es un historial retroactivo. Registrar conteos y duraciones, anonimizar identificadores y no compartir cargas completas.
- Los eventos de registro no equivalen a escrituras de estados en Recorder. No deducir una reducción de Recorder de esos conteos. Medir Recorder por separado únicamente con un método apropiado y comparable; si no se mide, comunicarlo como pendiente.

## Nombres y roaming

- Observar un cliente con nombre personalizado del router y otro con nombre de usuario en HA; anotar sus IDs antes del ensayo. Alternar conexión entre RC06, R3 y R4 en ambos órdenes si es posible, repetir observaciones y reiniciar HA de prueba. Comprobar nombre, ID, nodo asociado y presencia sin cambios manuales intermedios.
- Los registros históricos sin origen conocido conservan el nombre ante observaciones ambiguas; un renombrado puede no reflejarse automáticamente. Verificar cualquier renombrado legítimo solo si el propietario lo autoriza. No alterar nombres ni configuración del router como parte de la medición de base.
- Anotar sustituciones por MAC, cambios repetidos, entidades duplicadas o presencia incorrecta. Compartir únicamente información anonimizada.

## Wi-Fi de invitados

La lectura del panel puede comprobarse sin guardar. Activar, desactivar o modificar la Wi-Fi invitada requiere autorización expresa del propietario. Con autorización, registrar estado inicial y plan de recuperación, probar una operación cada vez, verificar la relectura y restaurar el estado inicial. Si la candidata no puede identificar el índice de la interfaz, detenerse: no forzar valores ni intentar operaciones alternativas.
