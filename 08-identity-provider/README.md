# 08 · Proveedor de identidad JWT

Servicio FastAPI con tokens RSA (`RS256`), contraseñas PBKDF2-SHA256 con sal y revocaciones persistentes. Es un laboratorio del flujo de contraseña y Bearer asociado a OAuth2; **no implementa un servidor OAuth2/OIDC completo**, discovery, authorization code/PKCE, consentimiento, refresh tokens ni registro de clientes.

```powershell
python scripts/init_labs.py
docker compose --env-file 08-identity-provider/.env -f 08-identity-provider/compose.yaml up -d --build
# Alternativa sin Docker
python scripts/run_local_module.py 08
```

Documentación interactiva: http://localhost:8001/docs. La cuenta local es `analyst`; su contraseña aleatoria se guarda en `data/login-password.txt`. El contenedor recibe solo el hash desde `.env`. La clave de firma se monta por un volumen de solo lectura tras copiarla con permisos del usuario del servicio. No se reescriben credenciales existentes al inicializar.

| Endpoint | Uso |
| --- | --- |
| `POST /login` | Formulario `application/x-www-form-urlencoded`: `username`, `password`, `scope` opcional; devuelve `access_token`, `token_type`, `expires_in` |
| `GET /verify?scope=pki:read` | Requiere `Authorization: Bearer …`; verifica firma, algoritmo fijo, `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, revocación y scopes |
| `POST /revoke` | JSON con `jti`; exige Bearer con `IDP_ADMIN_TOKEN`, diferente de un token de usuario |
| `GET /health` | Estado del servicio |

Tokens de cinco minutos por defecto, máximo una hora (`IDP_TOKEN_TTL`). Emisor `cybersecurity-labs`, audiencia `lab-services`; scopes asignados al usuario: `pki:read pki:sign`. El cliente puede pedir un subconjunto, nunca ampliarlos. El login limita a diez intentos por IP/minuto en un único proceso. El estado del limitador no se comparte entre réplicas; las revocaciones sí persisten en SQLite.

## Middleware reutilizable

`middleware.py` consulta `/verify` en el servidor configurado, de modo que respeta la revocación. Devuelve 401 si falta el Bearer, 403 si faltan scopes y 503 si no puede validar con el IDP. No sigue redirecciones ni utiliza proxies de entorno.

En otro servicio FastAPI, colocando el módulo en su ruta de importación:

```python
from fastapi import Depends, FastAPI
from middleware import require_scopes

app = FastAPI()
@app.get('/protected', dependencies=[Depends(require_scopes('http://localhost:8001', 'pki:read'))])
def protected():
    return {'ok': True}
```

Para Flask se proporciona `protect_flask(app, idp_url, scopes=('pki:read',), prefix='/api/')`. Puedes registrarlo después de construir la aplicación PKI 05 e instalar `httpx` en su entorno. **Es una protección adicional**: conserva la exigencia existente de `X-Admin-Token`; los clientes deben enviar también `Authorization`. La interfaz 05 no se modifica automáticamente para solicitar tokens. Para endpoints de firma selecciona `pki:sign`; no deduzcas scopes de datos enviados por el cliente.

En Docker, `localhost` representa el propio contenedor: usa una red compartida y el nombre del servicio cuando integres servicios. Para salir de loopback o de una red local confiable, configura HTTPS y una CA de confianza; no desactives la verificación de certificados.

Pruebas: `python -m pytest 08-identity-provider/tests/ -v`. Cubren emisión, claims, caducidad, firma ajena, scopes, falta de Bearer, revocación tras reinicio, rate limit y cierre del acceso cuando el IDP no responde.

Referencias: [JWT en FastAPI](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/), [validación de claims PyJWT](https://pyjwt.readthedocs.io/en/stable/usage.html).
