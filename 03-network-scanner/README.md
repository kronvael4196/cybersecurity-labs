# 03 · Automatizador de reconocimiento TCP

Escáner en Python estándar con IP/CIDR, concurrencia limitada y reportes JSON/HTML. Funciona sin Docker ni Nmap. Identifica puertos TCP abiertos y, opcionalmente, observa banners SSH, HTTP o FTP. Los indicios de HTTP sin TLS y FTP son observaciones para investigar, no una prueba de vulnerabilidad explotable.

## Uso

Desde esta carpeta:

```powershell
python scanner.py 127.0.0.1 --probe
python scanner.py 127.0.0.1 --ports 3001-3003,5005 --probe --output reports/laboratorios
python scanner.py ::1 --ports 80,443
```

Para una red de laboratorio que controles, declara explícitamente el alcance:

```powershell
python scanner.py 192.168.56.0/24 --scope 192.168.56.0/24 --ports 22,80,443 --workers 32 --timeout 0.5
```

El ejemplo de red no se ejecuta automáticamente. Ajusta `--scope` a los activos autorizados. Sin esa opción solo se permite loopback. Se admiten varios alcances repitiendo `--scope` y varios destinos separados por comas.

El programa genera `reports/scan.json` y `reports/scan.html`, salvo que cambies `--output`. Un mismo nombre de salida reemplaza el informe anterior. Abre el HTML en tu navegador.

## Interpretación

| Campo | Significado |
| --- | --- |
| `state=open` | La conexión TCP se estableció |
| `closed` | El destino rechazó la conexión |
| `filtered_or_unreachable` | Agotó el tiempo de espera; no distingue filtrado de falta de respuesta |
| `error` | Error de red local o de conexión, descrito en `error` |
| `service_hint` | Nombre habitual del puerto; no confirma el servicio |
| `service` | Protocolo reconocido en una respuesta; de otro modo `unconfirmed` |
| `findings` | Observaciones, como HTTP visible sin TLS |

`--probe` lee hasta 1024 bytes y envía `HEAD /` a puertos HTTP conocidos. Sin esa opción se limita a abrir y cerrar conexiones TCP. El HTML escapa las respuestas recibidas para que un banner no se ejecute como contenido activo.

Límites: 1024 direcciones, 65536 combinaciones IP/puerto, 128 workers y timeout de 0.05 a 10 segundos. No realiza autenticaciones, explotación, detección CVE, inspección TLS ni escaneo UDP. Es un punto de partida de reconocimiento, no un sustituto de un gestor de vulnerabilidades.

## Pruebas

```powershell
python -m unittest discover -s tests -v
```

Incluyen una conexión real a un servidor efímero de loopback, reconocimiento de banner, control de rangos y escape HTML.

Docker opcional: `docker build -t lab-scanner .`. Recuerda que `127.0.0.1` dentro de un contenedor representa ese contenedor; usa Python en el anfitrión para escanear los puertos de la colección.
