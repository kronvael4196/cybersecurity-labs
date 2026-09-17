# 06 · SOAR y respuesta automatizada

FastAPI recibe alertas del Mini SIEM en `POST /webhook/alert`, autentica el emisor con Bearer y ejecuta los adaptadores de `actions.py`. El modo predeterminado es **dry-run**. SQLite conserva un checkpoint por acción completada para evitar repeticiones al reenviar la misma alerta. Un fallo permite reintentar las acciones pendientes; una caída entre una acción externa y su checkpoint todavía puede duplicarla.

Desde la raíz, después de instalar `requirements-dev.txt`:

```powershell
python scripts/init_labs.py
docker compose --env-file 06-soar-automation/.env -f 06-soar-automation/compose.yaml up -d --build
# Alternativa sin Docker; primer plano, Ctrl+C para detener
python scripts/run_local_module.py 06
```

API/documentación: http://localhost:8080/docs. No ejecutes simultáneamente ambas variantes en el mismo puerto. El script local fuerza simulación. El contenedor usa un solo worker para serializar su ledger.

## Enviar un evento real del SIEM

Exporta una consulta de `mini-siem-alerts` a un JSON local o usa la evidencia versionada. El adaptador admite un `_source` individual o la respuesta `_search` con `hits.hits`.

```powershell
$env:SOAR_WEBHOOK_TOKEN = ((Get-Content 06-soar-automation/.env | Where-Object { $_ -like 'SOAR_WEBHOOK_TOKEN=*' }) -split '=',2)[1]
python 06-soar-automation/forward_alert.py docs/evidence/siem-alerts.json
```

El cuerpo requiere `@timestamp`, `event.kind=alert`, `source.ip` y `rule.id=ssh-repeated-failures`. Los campos adicionales del SIEM se admiten. `token_jti` es opcional: debe ser un identificador obtenido del proveedor de identidad, no un JWT completo. La API no acepta comandos, destinos HTTP ni reglas de firewall desde el payload.

Este reenvío es explícito. El detector 01 sigue funcionando por separado; para entrega continua el operador debe conectar su emisor de webhooks o programar la exportación/reenvío. No se afirma que exista una cola de entrega garantizada.

## Acciones reales

`compose.live.yaml` habilita `NET_ADMIN` y exige `SOAR_ALLOWED_NETWORKS`. Afecta **solo al namespace de red del contenedor SOAR**. No bloquea tráfico del host ni de otros contenedores; ese alcance requiere un adaptador para el firewall que realmente protege esos servicios. No se monta el socket Docker ni se usa red host.

```powershell
# Define primero SOAR_ALLOWED_NETWORKS con las redes de laboratorio autorizadas
docker compose --env-file 06-soar-automation/.env -f 06-soar-automation/compose.yaml -f 06-soar-automation/compose.live.yaml up -d --build
```

`block_ip` valida la IP, rechaza loopback/multicast/no especificadas, consulta si la regla ya existe y llama a iptables/ip6tables sin shell. Las reglas duran hasta eliminarse o recrear el contenedor. Para quitar una: `docker compose exec -u 0 soar iptables -D INPUT -s DIRECCION -j DROP` (usa los mismos archivos Compose y la IP aplicada).

`revoke_token` llama a `/revoke` usando `IDP_URL` y `IDP_ADMIN_TOKEN`. El destino debe ser alcanzable desde el contenedor: los puertos publicados solo en loopback no equivalen a una conexión entre contenedores. Usa una red Docker compartida explícita o un endpoint HTTPS accesible; no publiques el IDP indiscriminadamente.

`notify` acepta `NOTIFICATION_WEBHOOK_URL` de Slack o Discord por HTTPS. Sin esa variable devuelve `not_configured`. En dry-run nunca envía mensajes. No se envían credenciales ni el payload completo.

Pruebas: `python -m pytest 06-soar-automation/tests/ -v`. Comprueban autenticación, IP inválida, llamada a bloqueo, duplicados, reintento parcial, revocación y límites del modo real mediante mocks.

Referencia: [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/).
