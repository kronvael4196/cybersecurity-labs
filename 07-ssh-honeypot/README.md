# 07 · Honeypot SSH con geolocalización

Paramiko acepta cualquier par **usuario/contraseña** y registra el intento. La shell reconoce únicamente `whoami`, `id`, `pwd`, `ls`, `cat readme.txt`, `help` y `exit`. No ejecuta procesos del sistema, no admite SFTP ni forwarding. Limita conexiones simultáneas, longitud de entrada y duración de sesión.

```powershell
docker compose -f 07-ssh-honeypot/compose.yaml up -d --build
ssh -p 2223 visitante@127.0.0.1
# Alternativa sin Docker, en otra terminal
python scripts/run_local_module.py 07
```

El proceso escucha en **2222 dentro de Docker**. El host publica **127.0.0.1:2223** para convivir con el SSH del Mini SIEM (2222). Cambia `HONEYPOT_HOST_PORT` si necesitas otro puerto. El script Python directo `honeypot.py` usa 127.0.0.1:2222; el lanzador de la colección usa 2223.

`logs/honeypot.json` es **JSON Lines**: un objeto JSON por línea, con fecha UTC, IP, usuario, contraseña y resultado de geolocalización. En Docker reside en el volumen `honeypot-logs`. Contiene las credenciales introducidas deliberadamente en este laboratorio: utiliza identidades ficticias. Los logs y la clave SSH persistente de `data/` están excluidos de Git y de los artefactos CI. El acceso al archivo se restringe a su propietario donde el sistema admite permisos POSIX.

La geolocalización está desactivada inicialmente. Con `GEO_ENABLED=true`, IPs públicas consultan [ipapi.co por HTTPS](https://ipapi.co/api/), con timeout, caché de hasta 1024 IPs y tolerancia a errores/cuotas. Solo se envía la IP; las IP privadas no salen a la API. Una ubicación estimada no identifica a una persona. El lanzador local permanece sin consultas externas; para habilitarlas utiliza `honeypot.py` con la variable de entorno.

Pruebas: `python -m pytest 07-ssh-honeypot/tests/ -v`. Abren una conexión SSH real en un puerto efímero, verifican la clave de host, autentican, ejecutan la shell simulada y comprueban el JSON. Las pruebas geográficas usan mocks y no consumen la API.

Referencia: [API de servidor Paramiko](https://docs.paramiko.org/en/stable/api/server.html).
