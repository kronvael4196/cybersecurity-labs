# Estado de validación

Evidencias del 17 de septiembre de 2026. Las pruebas de contenedores se ejecutaron en runners Linux de GitHub Actions; las pruebas Python y el proxy HTTPS también se comprobaron en Windows.

## Pruebas automatizadas

| Suite | Pruebas | Cobertura |
| --- | ---: | --- |
| Mini SIEM | 8 | Colector, umbral, ventana, paginación y cooldown |
| Home Lab | 3 | SQLi, XSS y CSRF frente a sus correcciones |
| Escáner | 5 | Rangos, alcance, conexión TCP real, escape HTML y ocultación de credenciales en banners |
| Analizador VPN | 3 | Protocolos, HTTP, IPv6 y entrada vacía |
| PKI / TLS | 12 | RSA/ECC, firma, revocación, caducidad, CA ajena, persistencia, API y validación TLS estricta |
| **Total por versión de Python** | **31** | **Python 3.12 y 3.14** |

Las cuatro pruebas de navegador se ejecutan por separado: flujo PKI, Home Lab/escáner, informe pytest y dashboard Kibana. También se comprueban la sintaxis de los cuatro archivos Compose, el JavaScript de la PKI y los archivos versionados frente a patrones de secretos.

## Resultados funcionales

| Escenario | Resultado observado |
| --- | --- |
| PKI mediante Nginx HTTPS | Identidad `.p12` descargada, archivo firmado y firma válida comprobada desde Chromium |
| Integridad y revocación | El archivo modificado y el certificado revocado se rechazan |
| TLS | Certificado de localhost firmado por la CA del laboratorio; clientes y navegador validan la confianza sin omitir TLS |
| SSH → Logstash → Elasticsearch | Cinco fallos de contraseña y un acceso legítimo confirmados por eventos reales |
| Detección y Kibana | Una alerta por cinco fallos en 60 segundos; contadores visibles en el dashboard |
| Escáner → Home Lab | Puertos 3001, 3002 y 3003 abiertos e identificados como HTTP; informes JSON y HTML |
| Interfaces | Juice Shop y la aplicación corregida responden y se muestran en Chromium |

La [galería de evidencias](docs/evidence/README.md) conserva capturas y resultados seleccionados, con su ejecución de origen y commit. Los informes completos se descargan desde los artefactos de Actions durante 14 días.

## Entorno local y límites

En Windows se ejecutaron las suites Python y la prueba HTTP real de PKI para RSA/ECC. Nginx portátil sirve la aplicación en `https://localhost:8443`; su CA no se instala automáticamente en el almacén de confianza. Véase [HTTPS](docs/HTTPS.md).

Docker Desktop local informa `Virtual Machine Platform not enabled` y `No virtualization available`. No se modificaron características de Windows ni se reinició el equipo. **Los contenedores y las capturas de interfaz documentados arriba corresponden a GitHub Actions**, no a Docker en este equipo.

WireGuard conserva una comprobación pendiente: soporte del kernel, handshake, enrutamiento y captura real con TShark. Sus tres pruebas unitarias analizan filas de ejemplo. Validar su Compose no demuestra un túnel operativo.

La red interna del Home Lab y los enlaces a loopback se revisan en la configuración y se usan en las pruebas; no se presenta esto como una auditoría exhaustiva del aislamiento. ELK tiene la autenticación desactivada para el laboratorio local y no debe publicarse en Internet.

## Repetir

```powershell
.\.venv\Scripts\python.exe scripts/pytest_all.py
.\.venv\Scripts\python.exe scripts/check_secrets.py
```

El workflow [Labs CI](https://github.com/kronvael4196/cybersecurity-labs/actions/workflows/ci.yml) repite las pruebas de contenedores con cada push y pull request. También puede iniciarse manualmente desde Actions. Para repetir localmente, sigue los comandos de despliegue y pruebas del [README](README.md); Docker debe mostrar Client y Server sin errores. El laboratorio VPN incluye su propio `smoke.py` para la comprobación de túnel pendiente.
