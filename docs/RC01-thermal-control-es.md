# Control térmico del BE10000 / RC01

Comportamiento verificado en firmware **1.1.56**, analizando el programa instalado
`/usr/sbin/mitempcontrol` y contrastando sus datos por SSH, sin controlar el
ventilador ni cambiar ajustes. No extrapolar a otros modelos o firmwares.

## Temperatura

`misystem/get_temp_control` publica el estado de `mitempctrl`:

- `temp.curr` está en **°C** y representa la temperatura más alta de siete
  entradas: `wifi0`, `wifi1`, `wifi2` y los cuatro sensores que el controlador
  denomina `cpu0`–`cpu3` (thermal zones 7–10). No es una lectura exclusiva de CPU.
- `temp.target` es la consigna configurada del controlador.
- `temp.min` y `temp.max` son parámetros configurados, no el mínimo y máximo
  históricos observados. El diagnóstico interno tiene otro campo `highest_temp`.

Por ejemplo, una lectura interna dio radios 73/75/74 y sensores SoC 72/74/76/72:
`cur_temp` fue 76, igual que `temp.curr` de la API.

## Ventilador: medición y estimación

El controlador seleccionó estos archivos del chip **EMC2305**:

```text
/sys/bus/i2c/devices/1-002f/fan1_input
/sys/bus/i2c/devices/1-002f/pwm1
```

`fan1_input` es una lectura expresada en RPM. Pero `fan.speed` de la API no
siempre conserva esa lectura. El binario aplica este comportamiento:

```text
velocidad = lectura de fan1_input
si velocidad < 1000:
    velocidad = división entera de (PWM leído × 2500) / 255
publicar velocidad
```

Por tanto, la API expresa RPM **medidas o estimadas por el firmware**. No se
puede distinguir su origen solo por el número que devuelve ni reconstruir
el tacómetro original a partir de la API.

En las muestras se observó `fan1_input=960` mientras la API daba 0. Después la
API publicó 127, compatible con el PWM anterior de 13 (`13 × 2500 / 255`, división
entera). No demuestra que el ventilador girase realmente a 0, 127 o 960 RPM.

El controlador tenía un intervalo de **5000 ms** y la API publica su estado
guardado, sin leer el sensor en cada consulta HTTP. Las lecturas de archivos
tomadas justo después pueden pertenecer a otro momento del ciclo de control.

## Presentación recomendada

- «Temperatura de control térmico», en °C.
- «Velocidad del ventilador informada por el firmware», en RPM, indicando que
  puede ser estimada. No convertir automáticamente 0 en una alarma de parada.
- Para medir el tacómetro por separado hace falta una fuente que lea el archivo
  correspondiente; la consulta HTTP actual no permite recuperar esa lectura.
- No interpretar `fan.mode=1` hasta verificar su correspondencia funcional.

La convención de unidades de `fan1_input` está documentada por
[Linux hwmon](https://www.kernel.org/doc/Documentation/hwmon/sysfs-interface).
El algoritmo y el intervalo anteriores corresponden al firmware examinado.
