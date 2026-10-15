# Seguridad de autenticación y alertas de CodeQL

MiWiFi utiliza el protocolo de acceso LuCI del firmware del router. Su página
de acceso calcula `H(nonce + H(password + public_key))`, donde `H` es SHA-1 o
SHA-256, según el modo del firmware. La constante pública forma parte del
protocolo; no es un secreto ni una sal única para cada usuario. La fórmula se
comprobó en la página de acceso del RC01 local el 14 de octubre de 2026.
Las pruebas verifican ambos modos y contraseñas sintéticas con caracteres UTF-8.

CodeQL señala los dos hashes porque no son adecuados para proteger contraseñas
mediante un cálculo costoso. Existe una limitación real del protocolo: quien
capture un intercambio de acceso puede probar contraseñas sin contactar con el
router usando hashes rápidos. La integración no almacena un verificador propio
con esos hashes, pero eso no elimina el riesgo de la comunicación. Cambiar solo
el cliente a Argon2, bcrypt o PBKDF2 produciría una respuesta distinta y el router
rechazaría el acceso. Un protocolo más robusto necesita soporte del firmware.

Las alertas de SHA-1 y SHA-256 siguen visibles en CodeQL. Esta revisión no las
oculta, no las descarta como falsos positivos ni las presenta como corregidas.

## Reducir la exposición

- Utiliza una contraseña de administración del router larga y exclusiva.
- Prefiere HTTPS cuando el router lo admita. La detección automática prueba
  primero HTTPS y después HTTP; por tanto, `auto` no garantiza cifrado.
- Mantén Home Assistant y la administración del router en una red de confianza
  y restringe el acceso. HTTP no protege el intercambio de acceso ni las
  peticiones posteriores frente a quien pueda observar el tráfico.
- Protege la configuración y las copias de seguridad de Home Assistant: la
  integración necesita la credencial configurada para volver a autenticarse.

El mensaje sobre cambios de nodo de un cliente indica ahora solo que cambió su
asignación y cuántos registros de dispositivo vacíos se eliminaron. Ya no incluye
su MAC ni el identificador de la entrada de configuración. La prueba comprueba
tanto el mensaje formateado como los argumentos originales del log. Esta
corrección aborda la alerta concreta; no afirma que todos los diagnósticos o
mensajes de depuración carezcan de datos privados.

Referencias: [regla de CodeQL sobre contraseñas](https://codeql.github.com/codeql-query-help/python/py-weak-sensitive-data-hashing/)
y [regla sobre datos sensibles en logs](https://codeql.github.com/codeql-query-help/python/py-clear-text-logging-sensitive-data/).
