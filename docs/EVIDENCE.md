# Evidencias reproducibles

La [galería del portafolio](evidence/README.md) conserva una selección revisada de capturas y resultados junto con el commit y la ejecución que los produjeron.

## Local

`python scripts/pytest_all.py` genera resultados reales en `artifacts/pytest/`: consola, XML JUnit, HTML autocontenido y `summary.json`. Incluye los cinco proyectos y la comprobación del certificado TLS. Estos archivos no se agregan automáticamente a Git.

## GitHub Actions

Abre **Actions → Labs CI → ejecución → Artifacts**. Retención: 14 días.

| Artefacto | Contenido |
| --- | --- |
| `pytest-3.12`, `pytest-3.14` | HTML/JUnit y resumen de las cinco suites |
| `web-functional-evidence` | Firma válida/revocación por interfaz, Home Lab, puertos, captura pytest y prueba HTTP/TLS |
| `siem-functional-evidence` | Fallos SSH, alerta real, salida ELK y captura Kibana |

Las capturas se generan tras comprobar el resultado correspondiente y enmascaran el token PKI. No se exportan grabaciones, trazas con credenciales, PKCS#12, `.env` ni claves privadas. Los documentos de firma son ficticios y temporales.

## Escenarios

1. El navegador descarga una identidad `.p12`, firma un documento y vuelve a cargar los archivos para verificar. Comprueba firma válida, manipulación y revocación.
2. Cinco contraseñas erróneas y un acceso válido se ejecutan en SSH. Se comprueban eventos y alerta en Elasticsearch antes del dashboard.
3. El escáner prueba los puertos 3001–3003 publicados en loopback y exige tres servicios HTTP abiertos.
4. Los clientes HTTPS validan el certificado con la CA específica. El navegador usa el almacén del runner; no se desactiva TLS.

El estado de ejecución y sus logs son parte de la evidencia. Un dashboard vacío o una captura de una página sin validar su contenido no demuestra una prueba funcional exitosa.
