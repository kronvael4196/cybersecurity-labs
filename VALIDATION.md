# Estado de validación

Comprobaciones realizadas durante la implementación de la colección.

## Ejecutado correctamente

| Comprobación | Resultado |
| --- | --- |
| Mini SIEM: colector, umbral, ventana, paginación y cooldown | 8 pruebas aprobadas |
| Home Lab: SQLi, XSS y CSRF frente a sus correcciones | 3 pruebas aprobadas |
| Escáner: rangos, alcance, conexión TCP real y escape HTML | 4 pruebas aprobadas |
| Analizador VPN: protocolos, HTTP, IPv6 y entrada vacía | 3 pruebas aprobadas |
| PKI: emisión/firma/verificación RSA/ECC, revocación, caducidad, CA ajena, persistencia y API | 11 pruebas aprobadas |
| `docker compose config --quiet` | Válido en los cuatro proyectos con Compose |
| Compilación Python y `node --check` del JavaScript PKI | Sin errores |
| Servidor PKI real en loopback | `/health`, página, JS, CSS, CA y CRL responden 200 |
| Prueba HTTP real PKI | RSA/ECC: emisión, firma, verificación, archivo modificado y certificado revocado comprobados |
| Escáner contra la PKI local | Puerto 5005 abierto; HTTP reconocido; informes JSON/HTML generados |

La primera implementación aprobó 29 pruebas. La ampliación HTTPS añade una prueba de certificado de servidor: **30 pruebas aprobadas con pytest** en Windows. Los informes reales están en `artifacts/pytest/`; la prueba comprueba firma con la CA, SAN localhost/IP, uso serverAuth y correspondencia de clave.

## Pendiente por el entorno

El cliente Docker y Compose están instalados, pero `docker version` no consigue consultar el servidor: devuelve `500 Internal Server Error` en el endpoint de Docker Desktop Linux. Por eso **no se han construido ni arrancado los contenedores en esta sesión**. Validar un Compose no demuestra que sus imágenes arranquen.

Diagnóstico posterior: el backend de Docker informa `Virtual Machine Platform not enabled` y `No virtualization available`. No se han cambiado características de Windows ni reiniciado el equipo. Las pruebas de contenedores e interfaz se trasladaron al workflow de GitHub Actions; su estado debe comprobarse en la ejecución enlazada desde el README.

Quedan pendientes:

- ELK/SSH: ingestión real a Logstash y alerta consultable en Kibana.
- Home Lab: arranque de Juice Shop y aislamiento de la red Docker.
- WireGuard: soporte del kernel, handshake, enrutamiento, captura PCAP y ejecución real de TShark. Las pruebas unitarias del analizador usan filas de ejemplo, no una captura de red.
- PKI dentro de Docker: el flujo HTTP sí fue probado ejecutando Python directamente en Windows.
- Revisión visual en navegador: no hubo un navegador conectado disponible. Se comprobaron los recursos HTTP y la sintaxis JavaScript, pero no el renderizado ni los clics de la interfaz.

## Repetir las pruebas integrales

Cuando `docker version` muestre Client y Server sin error:

1. En `01-mini-siem`, sigue su README para crear `.env`, iniciar ELK y esperar el pipeline; ejecuta `python scripts/smoke.py`.
2. En `02-vulnerable-home-lab`, ejecuta `docker compose up -d --build` y visita los tres puertos documentados.
3. En `04-vpn-traffic-monitor`, ejecuta `docker compose up -d --build` y `python smoke.py`.
4. Para probar la PKI con Docker, detén primero su proceso Python local, inicia el Compose de `05-pki-digital-signature` y ejecuta `python smoke.py`.

Desde la raíz puedes repetir las pruebas sin Docker con `.\.venv\Scripts\python.exe scripts/test_all.py`.
