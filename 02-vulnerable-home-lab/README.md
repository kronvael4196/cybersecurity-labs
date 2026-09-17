# 02 · Entorno local de prácticas vulnerables

Tres aplicaciones sobre una red Docker interna: OWASP Juice Shop, un pequeño servicio deliberadamente vulnerable y su variante corregida. Los ejercicios propios permiten revisar exactamente qué cambia en el código, además de practicar en Juice Shop.

Un gateway Nginx publica únicamente los tres puertos de loopback y reenvía a cada aplicación. Las aplicaciones permanecen solo en la red interna y no obtienen una ruta de salida a Internet. El gateway tiene una red de entrada separada, sin permitir destinos de proxy arbitrarios.

## Arranque

Desde esta carpeta:

```powershell
docker compose up -d --build
docker compose ps
```

| Aplicación | URL |
| --- | --- |
| OWASP Juice Shop 19.0.0 | http://127.0.0.1:3001 |
| Ejercicios vulnerables | http://127.0.0.1:3002 |
| Ejercicios corregidos | http://127.0.0.1:3003 |

La versión de Juice Shop se fija para que los ejercicios no cambien con cada descarga. El objetivo es una aplicación intencionalmente vulnerable. Los contenedores no tienen volúmenes con documentos personales ni acceso al socket de Docker. Los puertos son solo locales y la red `internal` no proporciona salida normal a Internet. No publiques estos puertos en tu LAN ni cambies el enlace a `0.0.0.0` en Compose.

## Prácticas con evidencia

### SQLi

En el formulario de búsqueda, introduce `' OR 1=1 --`. La variante vulnerable devuelve tanto el producto público como la nota privada ficticia. La corregida interpreta la entrada como texto y no devuelve la nota.

En [lessons/app.py](lessons/app.py), compara la consulta construida con un f-string con la consulta parametrizada que usa `?`. La corrección mantiene la condición `public=1` separada de la entrada del usuario.

### XSS reflejado

En el formulario de mensaje, prueba `<script>alert('lab')</script>`. En la variante vulnerable el navegador puede ejecutar el script; la corregida muestra el texto escapado. Su plantilla usa el autoescape de Jinja y añade una política CSP como defensa adicional.

### CSRF

La operación `/profile` cambia el correo ficticio de la sesión. Compara una petición POST sin campo `csrf`: la variante vulnerable la acepta; la corregida responde 403. El formulario legítimo incluye el token y sigue funcionando. Las cookies tienen nombres diferentes para no mezclar ambas sesiones.

Esto demuestra el requisito del token; el comportamiento de una prueba desde otro origen también depende de las reglas SameSite del navegador. Los ejercicios no implementan cuentas reales ni un sistema completo de autenticación.

| Caso | Evidencia vulnerable | Corrección | Resultado esperado |
| --- | --- | --- | --- |
| SQLi | Se obtiene la nota privada | Parámetros SQL | La entrada no cambia la estructura SQL |
| XSS | Se inserta HTML ejecutable | Autoescape + CSP | El contenido se muestra como texto |
| CSRF | POST sin token aceptado | Token ligado a sesión | 403 sin token; 200 con token |

Documenta tus hallazgos con [docs/informe.md](docs/informe.md). Para Juice Shop comienza por sus retos introductorios y anota el hallazgo, la causa, la corrección propuesta y cómo comprobarías esa corrección.

## Ejecutar los ejercicios sin Docker

Desde la raíz de la colección, instala `requirements-dev.txt`. Luego, en esta carpeta:

```powershell
cd lessons
$env:LAB_MODE = 'vulnerable'
$env:PORT = '3002'
..\..\.venv\Scripts\python.exe app.py
```

En otra terminal repite con `LAB_MODE='hardened'` y `PORT='3003'`. De forma predeterminada el proceso local escucha solo en `127.0.0.1`. Juice Shop requiere su instalación aparte o Docker.

Pruebas, desde `lessons`:

```powershell
..\..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Las aplicaciones propias usan datos efímeros y ficticios. Reiniciar invalida las sesiones. Para detener los contenedores: `docker compose down`.

Referencia: [guía oficial para ejecutar OWASP Juice Shop](https://help.owasp-juice.shop/part1/running.html).
