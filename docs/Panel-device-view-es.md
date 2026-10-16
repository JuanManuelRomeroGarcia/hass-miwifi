# Vista de dispositivos y revisión móvil del panel

Preparación local, todavía sin publicar. No cambia la versión de MiWiFi ni añade
consultas al router. El #357 propone una tabla con columnas configurables.

En **Dispositivos MiWiFi** puedes elegir Tarjetas o Tabla, buscar por nombre, IP,
MAC, nodo o conexión y ordenar pulsando el encabezado de una columna. El selector
**Columnas visibles** permite mostrar los campos necesarios. El nombre permanece
visible y fijo al desplazar la tabla horizontalmente en móvil. Las tarjetas siguen
disponibles; en ellas se mantienen los controles de acceso WAN.

Vista, columnas y orden se guardan en ese navegador. La búsqueda y los datos de los
dispositivos no se guardan. Si el almacenamiento del navegador está bloqueado, la
vista sigue funcionando, aunque no conserva las preferencias al volver a abrirla.
**Mostrar desconectados** incluye los dispositivos fuera de casa y no disponibles.
Los contadores superiores siguen mostrando el total, incluso al buscar.

La revisión también ajusta navegación, cuadrículas, nombres largos y controles de
Estado, Mesh, Ajustes, DHCP y puertos en pantallas estrechas. La topología distribuye
sus nodos en varias filas en móvil. El diálogo de puertos cabe en ventanas pequeñas,
permite desplazarse verticalmente, tiene Cancelar y admite Escape y navegación con
Tab. Las etiquetas nuevas están en los ocho idiomas del panel.

## Probar antes de publicar

1. Conserva una copia de la carpeta `custom_components/miwifi/www` instalada y copia
   la carpeta `www` local completa por SFTP. No necesitas copiar `tools` ni `docs` a HA.
2. Recarga el panel evitando la caché. En escritorio puedes usar Ctrl+F5. Si sigue
   apareciendo la vista anterior en la app móvil, comprueba su caché del frontend.
   La versión continúa siendo 3.10.0 durante esta preparación local.
3. Comprueba las ocho páginas en escritorio, tableta y móvil. Prueba nombres largos,
   varios nodos y temas claro/oscuro. En la tabla, desliza horizontalmente y confirma
   que el nombre permanece visible; abre Columnas visibles y cambia la selección.
4. Busca un cliente por nombre/IP/nodo, ordena, muestra desconectados y recarga:
   vista, columnas y orden deben conservarse; la búsqueda debe quedar vacía.
5. Comprueba que un cambio real de estado/IP/conexión se refleja durante el uso
   normal de HA y al volver a la página. Valida también con un usuario no administrador.
6. Abre y cancela el diálogo de puertos sin guardar. Para comprobar cambios de acceso
   WAN en HA, usa únicamente un cliente de prueba acordado y restaura su estado.

## Comprobaciones locales

`node tools/test_devices_ui.mjs` comprueba búsqueda, orden numérico de nombres/IP y
velocidades, columnas, preferencias, almacenamiento bloqueado, estados no disponibles,
permisos y errores WAN y traducciones. También se ejecutan los scripts existentes de
MAC privadas y DHCP y `tools/check_frontend_packaging.py`.

Para ver las páginas reales con respuestas ficticias, ejecuta
`python tools/preview_panel.py` y abre `http://127.0.0.1:8767`. Puedes cambiar ancho,
idioma, tema y permisos. Las operaciones de esa vista previa no llegan a HA ni al router.
Se ha revisado el diseño a 320, 390, 768 y 1280 píxeles; estas pruebas no sustituyen
la comprobación pendiente en la app de HA y en un teléfono real.
