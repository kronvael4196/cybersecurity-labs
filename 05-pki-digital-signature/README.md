# 05 · Certificados y firma digital

Servicio web Flask con una CA local, emisión RSA/ECC, exportación PKCS#12 cifrada, firmas separadas y revocación. La interfaz permite completar todo el flujo sin invocar la API manualmente.

## Arranque local

Instala las dependencias comunes según el README raíz. Desde esta carpeta:

```powershell
..\.venv\Scripts\python.exe init_env.py
..\.venv\Scripts\python.exe app.py
```

Abre http://127.0.0.1:5005. Copia el valor de `PKI_ADMIN_TOKEN` de `.env` en el campo de acceso y pulsa **Conectar**. El token permanece en el campo de la página; no se guarda en localStorage ni se incorpora a las URLs.

Alternativa Docker:

```powershell
python init_env.py
docker compose up -d --build
```

En Docker la interfaz se sirve en **https://localhost:8443** mediante Nginx; el puerto 5005 no se publica. Exporta y verifica la CA según [docs/HTTPS.md](../docs/HTTPS.md). La ejecución directa con Python conserva el acceso HTTP local de desarrollo.

`init_env.py` genera secretos aleatorios y no reemplaza un `.env` existente. La CA se crea al primer arranque. Su clave se cifra con `PKI_CA_PASSWORD`; conserva esa contraseña junto con una copia protegida de los datos. Cambiarla en `.env` no vuelve a cifrar la clave existente y hará fallar el siguiente arranque.

La instancia local guarda datos en `data/`. Docker usa el volumen `pki-data`: son almacenes diferentes. No ejecutes ambos procesos a la vez sobre el mismo puerto ni compartas el almacén entre varios procesos de inicialización.

## Flujo de práctica

1. Emite una identidad ECC P-384 o RSA 2048, de 1 a 365 días, con contraseña PKCS#12 de al menos 12 caracteres.
2. Guarda el `.p12`. Contiene la clave privada cifrada, el certificado y la CA pública; el servidor no conserva la clave privada del usuario.
3. En **Firmar**, selecciona un archivo, el `.p12` y su contraseña. Descarga `signature.json`.
4. En **Verificar**, selecciona el archivo original y el JSON. Debe aparecer **Firma válida**.
5. Modifica una copia del archivo y repite: la verificación debe fallar.
6. Revoca el certificado desde la tabla. Incluso la firma original será rechazada en las verificaciones posteriores según el estado actual de revocación.

El límite del servidor es 12 MB para toda la petición multipart; la interfaz limita cada archivo a 10 MB. No uses esta CA ni sus claves para identidades reales.

## Qué se comprueba

- Firma criptográfica: RSA-PSS/SHA-256 o ECDSA/SHA-256.
- Integridad de los bytes del archivo y hash SHA-256 del paquete.
- Firma del certificado con la CA local y coincidencia exacta con el registro de emisión.
- Vigencia de certificado y CA y uso permitido de firma digital.
- CRL local firmada, vigente y generada a partir del registro actual de revocaciones.

La CA usa RSA 3072 y la clave se almacena como PKCS#8 cifrado. Certificados, revocaciones y auditoría de emisión/firma/revocación se guardan en SQLite. Los uploads se procesan en memoria: no se guardan los archivos firmados ni PKCS#12 importados. El proceso debe manejar temporalmente las claves descifradas para firmar.

## API

Las rutas `/api/*` requieren la cabecera `X-Admin-Token`. No se habilita CORS ni se usan cookies para autorizar operaciones.

| Método | Ruta | Entrada / salida |
| --- | --- | --- |
| GET | `/api/certificates` | Lista de certificados y revocaciones |
| POST | `/api/certificates` | JSON: `name`, `algorithm` (`RSA`/`ECC`), `days`, `password`; descarga `.p12` |
| POST | `/api/certificates/{serial}/revoke` | JSON con `reason` opcional |
| POST | `/api/sign` | Multipart: `file`, `p12`, `password`; firma JSON |
| POST | `/api/verify` | Multipart: `file`, `signature`; resultado JSON |
| GET | `/ca.pem` | CA pública |
| GET | `/crl.pem` | CRL actual firmada |
| GET | `/health` | Estado del proceso |

## Límites del proyecto

Es una PKI de aprendizaje con un administrador, una raíz local y certificados de usuario directamente emitidos por ella. No valida cadenas públicas, no consulta OCSP/CRL externas y no importa certificados ajenos para firmar. No ofrece firma PDF/PAdES/CAdES, sellado de tiempo confiable, identidad verificada ni efectos legales por sí misma. Un archivo PDF se puede firmar como bytes, pero no se inserta una firma nativa dentro del PDF.

La revocación se evalúa al verificar, sin reconstruir confianza histórica. El endpoint CRL exporta una lista válida durante 24 horas; un consumidor externo debe actualizarla para conocer nuevas revocaciones. La aplicación usa siempre una lista recién generada.

El servidor HTTP se publica solo en loopback. Para un despliegue compartido harían falta, entre otras decisiones, TLS, autenticación por usuario, protección de la CA y políticas de respaldo/rotación. Esta implementación no se despliega como servicio público.

## Pruebas

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Se prueban ambos algoritmos, API completa, contraseña incorrecta, manipulación, caducidad, CA ajena, revocación, persistencia y exigencia de token. Los certificados de prueba se crean en directorios temporales.

Con el servidor iniciado, puedes ejecutar una prueba HTTP real:

```powershell
python smoke.py
```

Esta prueba lee el token de `.env`, emite dos identidades llamadas `Prueba integral`, comprueba firma/manipulación/revocación y deja ambas identidades revocadas en el registro. No escribe PKCS#12 ni contraseñas en disco o en la consola.

Referencias: [X.509 y CRL en cryptography](https://cryptography.io/en/latest/x509/reference/), [serialización PKCS#12](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs12).
