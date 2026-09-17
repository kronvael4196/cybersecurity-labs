# HTTPS con la CA del laboratorio

`tls-init` abre o crea la CA del volumen PKI y emite un certificado de servidor de 30 días, con SAN `localhost`, `127.0.0.1` y `::1` y uso `serverAuth`. Nginx recibe el volumen TLS en modo lectura, nunca la clave de la CA. Flask no publica directamente el puerto 5005 en Docker.

Se habilitan TLS 1.2/1.3 y una redirección HTTP en el puerto 8085. No se fija HSTS sobre `localhost`: esa política afectaría también a los otros laboratorios HTTP del mismo nombre, aunque usen puertos diferentes.

Desde `05-pki-digital-signature`:

```powershell
docker compose up -d --build
New-Item -ItemType Directory -Force tls | Out-Null
docker compose cp tls-init:/app/tls/ca.pem tls/ca.pem
curl.exe --cacert tls/ca.pem https://localhost:8443/health
```

En Linux/macOS usa `mkdir -p tls` y `curl`. La respuesta debe ser `{"status":"ok"}` sin `-k` ni `--insecure`.

El navegador debe confiar en la CA para evitar advertencias. Si decides confiar en ella en tu cuenta Windows, verifica primero que el archivo provenga de tu volumen y ejecuta:

```powershell
certutil -user -addstore Root tls/ca.pem
```

Esto modifica persistentemente la confianza de tu cuenta; la automatización no lo ejecuta en tu equipo. No importes una CA ajena. GitHub Actions instala su CA temporal únicamente dentro del runner desechable, en el sistema y el almacén NSS de Chromium.

Prueba API por HTTPS, desde la carpeta PKI:

```powershell
$env:PKI_BASE_URL = 'https://localhost:8443'
$env:SSL_CERT_FILE = (Resolve-Path tls/ca.pem).Path
python smoke.py
```

Renovación con la misma CA:

```powershell
docker compose run --rm tls-init
docker compose exec proxy nginx -t
docker compose exec proxy nginx -s reload
```

La renovación reemplaza la clave/certificado TLS. El certificado anterior sigue siendo válido hasta caducar si alguien conserva su clave. Los certificados TLS no se registran como identidades de firma ni se gestionan con la revocación de la interfaz. No hay OCSP ni distribución automática de CRL para TLS.

No borres el volumen PKI ni cambies `PKI_CA_PASSWORD` sin conservar su clave y secreto originales. Recrear la CA exige retirar la raíz antigua y confiar expresamente en la nueva.

Referencia: [configuración HTTPS de Nginx](https://nginx.org/en/docs/http/configuring_https_servers.html).

## Windows sin Docker

Con el entorno Python preparado, ejecuta desde la raíz:

```powershell
.\scripts\start_https_local.ps1
```

El script descarga Nginx 1.28.3 portátil del sitio oficial en `artifacts/nginx-local`, emite el certificado con la CA de `05-pki-digital-signature/data`, inicia la PKI si no responde y sirve HTTPS en loopback. No instala la CA en Windows ni modifica PATH. Al repetirlo renueva el certificado y recarga Nginx. El backend HTTP local de desarrollo sigue en 5005; Docker es la variante que no publica ese backend.

Para detener solo ese proxy portátil:

```powershell
Push-Location artifacts/nginx-local/nginx-1.28.3
.\nginx.exe -s quit -c conf/lab.conf
Pop-Location
```
