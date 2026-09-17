# Portable HTTPS fallback for Windows when Docker virtualization is unavailable.
$ErrorActionPreference = 'Stop'
$labRoot = Split-Path -Parent $PSScriptRoot
$pkiFolder = Join-Path $labRoot '05-pki-digital-signature'
$pythonPath = Join-Path $labRoot '.venv\Scripts\python.exe'
$runtimeFolder = Join-Path $labRoot 'artifacts\nginx-local'
$nginxVersion = '1.28.3'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Crea .venv e instala requirements-dev.txt primero.' }
& $pythonPath (Join-Path $pkiFolder 'init_env.py')
& $pythonPath (Join-Path $pkiFolder 'tls_setup.py')
if ($LASTEXITCODE -ne 0) { throw 'No se pudo emitir el certificado TLS.' }
New-Item -ItemType Directory -Path $runtimeFolder -Force | Out-Null
$nginxFolder = Join-Path $runtimeFolder "nginx-$nginxVersion"
$nginxExe = Join-Path $nginxFolder 'nginx.exe'
if (-not (Test-Path -LiteralPath $nginxExe)) {
    $archivePath = Join-Path $runtimeFolder 'nginx.zip'
    Invoke-WebRequest -Uri "https://nginx.org/download/nginx-$nginxVersion.zip" -OutFile $archivePath
    Expand-Archive -LiteralPath $archivePath -DestinationPath $runtimeFolder -Force
}
$certificateFolder = (Join-Path $pkiFolder 'tls').Replace('\', '/')
$configPath = Join-Path $nginxFolder 'conf\lab.conf'
$nginxConfig = @'
worker_processes 1;
pid logs/nginx.pid;
events { worker_connections 256; }
http {
    include mime.types;
    server_tokens off;
    client_max_body_size 12m;
    server {
        listen 127.0.0.1:8443 ssl;
        server_name localhost;
        ssl_certificate "CERT_PATH/server.pem";
        ssl_certificate_key "CERT_PATH/server.key";
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_tickets off;
        location / {
            proxy_pass http://127.0.0.1:5005;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $remote_addr;
        }
    }
}
'@
$nginxConfig.Replace('CERT_PATH', $certificateFolder) | Set-Content -LiteralPath $configPath -Encoding Ascii
try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:5005/health' -TimeoutSec 3 | Out-Null
} catch {
    Start-Process -FilePath $pythonPath -ArgumentList 'app.py' -WorkingDirectory $pkiFolder -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtimeFolder 'pki.stdout.log') -RedirectStandardError (Join-Path $runtimeFolder 'pki.stderr.log') | Out-Null
    & $pythonPath (Join-Path $PSScriptRoot 'wait_http.py') 'http://127.0.0.1:5005/health' --seconds 30
    if ($LASTEXITCODE -ne 0) { throw 'La PKI no está disponible.' }
}
Push-Location $nginxFolder
try {
    & $nginxExe -t -c conf/lab.conf
    if ($LASTEXITCODE -ne 0) { throw 'Configuración Nginx inválida.' }
    $nginxProcessId = 0
    $pidText = if (Test-Path -LiteralPath 'logs/nginx.pid') { Get-Content -LiteralPath 'logs/nginx.pid' -Raw } else { '' }
    $runningProxy = $null
    if ([int]::TryParse($pidText, [ref]$nginxProcessId) -and $nginxProcessId -gt 0) {
        $runningProxy = Get-Process -Id $nginxProcessId -ErrorAction SilentlyContinue
    }
    if ($runningProxy -and $runningProxy.Path -eq $nginxExe) {
        & $nginxExe -s reload -c conf/lab.conf
        if ($LASTEXITCODE -ne 0) { throw 'No se pudo recargar Nginx; comprueba el PID local.' }
    } else {
        Start-Process -FilePath $nginxExe -ArgumentList @('-c', 'conf/lab.conf') -WorkingDirectory $nginxFolder -WindowStyle Hidden | Out-Null
    }
} finally { Pop-Location }
& $pythonPath (Join-Path $PSScriptRoot 'wait_http.py') 'https://localhost:8443/health' --ca (Join-Path $pkiFolder 'tls\ca.pem') --seconds 30
if ($LASTEXITCODE -ne 0) { throw 'La verificación HTTPS falló.' }
Write-Output 'PKI disponible en https://localhost:8443. No se modificó el almacén de confianza de Windows.'
