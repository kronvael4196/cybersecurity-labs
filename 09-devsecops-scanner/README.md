# 09 · Escáner DevSecOps de secretos

CLI sin dependencias Python externas. Recorre el árbol buscando tokens GitHub/Slack, claves de acceso AWS, JWT, cabeceras de claves privadas PEM y asignaciones literales de contraseñas/API keys. `rules.json` contiene patrones, exclusiones y prefijos de placeholders.

```powershell
python 09-devsecops-scanner/scanner.py .
python -m pytest 09-devsecops-scanner/tests/ -v
```

| Código de salida | Significado |
| --- | --- |
| 0 | Escaneo completado sin coincidencias |
| 1 | Una o más coincidencias |
| 2 | Ruta, configuración, lectura u otra condición que impide completar el escaneo |

El JSON informa ruta, línea y regla, **sin mostrar el secreto ni la línea de código**. `.git`, entornos virtuales, dependencias, imágenes y `.gitignore` están excluidos. No sigue enlaces simbólicos; omite binarios con bytes nulos. Un archivo candidato mayor de 5 MiB interrumpe el análisis con código 2 en lugar de dar un resultado limpio incompleto.

En repositorios Git utiliza `git check-ignore` para respetar reglas anidadas y negaciones de `.gitignore`. Los archivos ya versionados se escanean incluso si coinciden con una exclusión de Git. Fuera de Git se aplican únicamente las exclusiones de `rules.json`; Git es necesario para interpretar `.gitignore`.

Las coincidencias deliberadas de una fixture pueden exceptuarse en su misma línea mediante `# secret-scan: allow -- motivo descriptivo`. Deben revisarse como código; no se excluyen directorios completos de tests. Los tests generan secretos ficticios temporalmente, verifican código 1 real y comprueban que no aparecen en la salida.

Es una detección heurística: puede producir falsos positivos y no detecta todos los formatos, secretos cifrados/codificados ni historial Git. No comprueba si una credencial funciona ni consulta servicios externos. Si aparece una credencial real, revócala y revisa el historial; ignorar el archivo no revierte una publicación previa.

El job `devsecops-scan` bloquea CI si hay hallazgos. Se mantiene además `scripts/check_secrets.py`, que revisa el índice Git y prohíbe versionar claves, identidades y archivos de datos locales.
