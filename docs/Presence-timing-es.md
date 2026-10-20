# Tiempos de consulta y presencia

Disponible desde v3.13.0.

Los valores se mantienen configurables para adaptarse a cada firmware y red.
Al guardar una entrada con seguimiento activado, el formulario exige:

**Permanencia mínima en línea ≥ intervalo de escaneo + espera de solicitudes.**

Es un mínimo de configuración, no una garantía de disponibilidad ni un límite
máximo de un ciclo completo: hay consultas secuenciales, reintentos y nodos que
reciben los clientes del principal. En mesh considera el nodo que informa más
despacio y aumenta el margen si hace falta. No se fuerzan los mismos tiempos a
todas las redes ni se modifican automáticamente los ajustes existentes.

| Ajuste | Significado y efecto |
| --- | --- |
| Intervalo de escaneo | Tiempo entre consultas programadas. Las peticiones añaden duración; el intervalo real entre observaciones puede ser mayor. Consultar más a menudo aumenta la carga del router. |
| Permanencia mínima en línea | Margen desde la última observación antes de considerar ausente al cliente. Un margen corto causa falsas salidas; uno largo retrasa la detección de una desconexión real. La evaluación depende de las siguientes actualizaciones. |
| Espera de solicitudes | Tiempo de espera de una petición; ciertas consultas tienen un límite más corto. No es el tiempo máximo de una actualización completa ni el margen de presencia. |
| Días desde última actividad | Retención de clientes antiguos. Puede eliminar sus entidades al superar el plazo si no se conservan en otro nodo; es independiente del calendario de autopurga. |
| Autopurga cada X días | Frecuencia de la limpieza programada, que se ejecuta con sus filtros conservadores. 0 desactiva ese programador, pero no desactiva otras limpiezas como la retención por actividad. |

## Ejemplos

- Escaneo 20 s y espera 20 s: mínimo permitido 40 s; empezar con 60 s da margen adicional.
- Escaneo 30 s y espera 20 s: mínimo permitido 50 s; empezar con 60 s.
- Escaneo 60 s y espera 20 s: mínimo permitido 80 s; 60 s ya no basta para guardar.

Las altas nuevas proponen 60 s de presencia, con los escaneos/esperas habituales
30/20. Una configuración anterior conserva sus valores al arrancar y al abrir
el formulario. Si son demasiado cortos, al guardar se muestra el mínimo necesario
junto al campo, sin guardar cambios ni probar las credenciales. Los valores
introducidos se conservan para corregirlos. Con seguimiento desactivado, la regla
de presencia no bloquea el guardado.

## Nuestra prueba

Mantener escaneo principal 20 s, nodo 30 s, espera 20 s y presencia 60 s en ambos.
Dejar la autopurga en 0. Observar 10 minutos sin desconectar el Wi-Fi y luego
comprobar una salida/entrada deliberada, sin aumentar otros tiempos a la vez.
Las capturas mostraban salidas simultáneas y márgenes 15/20 s frente a lecturas
aproximadas 24/34 s; aumentar el margen es la comprobación inicial, no una prueba
de que cualquier futura oscilación tenga esa misma causa.
