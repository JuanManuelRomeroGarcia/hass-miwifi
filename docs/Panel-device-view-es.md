# Vista de dispositivos y revisión móvil del panel

Disponible desde **v3.11.0**. Las vistas no añaden consultas al router. El #357
propone la tabla de dispositivos con columnas configurables.

En **Estado**, el selector **Tarjetas / Lista** cambia la presentación de sistema,
Internet (incluido WAN2 cuando está activado) y contadores del principal y los nodos.
La lista usa dos columnas, Datos y Valor, con ajuste de texto también en móvil.
Las tarjetas ajustan IP y textos largos a su anchura. Esta preferencia se guarda
por separado de la vista de dispositivos y solo contiene el tipo de vista.
Los datos de WAN2 proceden del #358, incluido en la misma versión.

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

## Instalación y comprobaciones

La instalación normal se realiza mediante HACS: actualiza a 3.11.0, reinicia HA
y refresca el panel. No necesitas instalar un frontend aparte. El mantenedor ha
confirmado las vistas combinadas en su HA real, tanto en escritorio como en móvil.
Para probar manualmente una compilación de desarrollo:

1. Conserva una copia de la carpeta `custom_components/miwifi/www` instalada y copia
   la carpeta `www` local completa por SFTP. No necesitas copiar `tools` ni `docs` a HA.
   Si el backend instalado aún no incluye main con #358, conserva una copia de toda
   la integración, copia `custom_components/miwifi` completa y reinicia HA. La carpeta
   `www` por sí sola no instala el soporte de WAN2 del backend.
2. Recarga el panel evitando la caché. En escritorio puedes usar Ctrl+F5. Si sigue
   apareciendo la vista anterior en la app móvil, comprueba su caché del frontend.
   Comprueba que la compilación y todos los archivos del panel corresponden a la
   misma versión; los archivos de esta publicación usan 3.11.0.
3. Comprueba las ocho páginas en escritorio, tableta y móvil. Prueba nombres largos,
   varios nodos y temas claro/oscuro. En la tabla, desliza horizontalmente y confirma
   que el nombre permanece visible; abre Columnas visibles y cambia la selección.
4. Busca un cliente por nombre/IP/nodo, ordena, muestra desconectados y recarga:
   vista, columnas y orden deben conservarse; la búsqueda debe quedar vacía.
   En Estado, alterna Tarjetas/Lista y confirma que ambas muestran los mismos datos,
   que WAN2 aparece solo si está activado y que una actualización conserva la vista.
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
La vista Lista de Estado también tiene pruebas automáticas de datos y preferencias.
El mantenedor ha confirmado su presentación en escritorio y móvil en HA real;
esto no acredita todos los navegadores, temas o modelos de teléfono.
