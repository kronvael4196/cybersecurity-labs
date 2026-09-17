const $ = (id) => document.getElementById(id);
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
async function api(path, options = {}) {
  const token = $('token').value.trim();
  if (!token) throw new Error('Introduce el token de acceso.');
  const response = await fetch(path, { ...options, headers: { ...options.headers, 'X-Admin-Token': token } });
  if (!response.ok) { const body = await response.json(); throw new Error(body.error || 'No se pudo completar la operación.'); }
  return response;
}
function download(blob, name) {
  const url = URL.createObjectURL(blob); const link = document.createElement('a');
  link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function busy(button, action) {
  button.disabled = true;
  try { await action(); } catch (error) { status(error.message, true); }
  finally { button.disabled = false; }
}
async function refresh() {
  const rows = await (await api('/api/certificates')).json();
  $('certificates').replaceChildren();
  if (!rows.length) { const row = $('certificates').insertRow(); const cell = row.insertCell(); cell.colSpan = 5; cell.textContent = 'Todavía no hay certificados. Emite tu primera identidad.'; }
  for (const item of rows) {
    const row = $('certificates').insertRow(); row.title = `Serie: ${item.serial}`;
    const expired = new Date(item.expires_at) < new Date();
    for (const value of [item.name, item.algorithm, new Date(item.expires_at).toLocaleDateString(), item.revoked_at ? 'Revocado' : expired ? 'Caducado' : 'Vigente']) row.insertCell().textContent = value;
    const cell = row.insertCell();
    if (!item.revoked_at) {
      const button = document.createElement('button'); button.textContent = 'Revocar'; cell.append(button);
      button.addEventListener('click', () => {
        if (!confirm(`¿Revocar el certificado de ${item.name}? No podrá volver a utilizarse para firmar.`)) return;
        busy(button, async () => {
          await api(`/api/certificates/${item.serial}/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reason: 'Revocación desde el laboratorio' }) });
          await refresh(); status('Certificado revocado. Las verificaciones posteriores lo rechazarán.');
        });
      });
    } else cell.textContent = '—';
  }
}
for (const id of ['connect', 'refresh']) $(id).addEventListener('click', () => busy($(id), async () => { await refresh(); status('Conectado a la CA local.'); }));
$('issue').addEventListener('submit', (event) => {
  event.preventDefault(); const form = event.currentTarget;
  busy(form.querySelector('button'), async () => {
    const data = Object.fromEntries(new FormData(form)); data.days = Number(data.days);
    status('Generando clave y certificado…');
    const response = await api('/api/certificates', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    download(await response.blob(), `certificate-${response.headers.get('X-Certificate-Serial')}.p12`);
    form.elements.password.value = ''; await refresh(); status('Identidad emitida. Guarda el PKCS#12 y su contraseña.');
  });
});
for (const id of ['sign', 'verify']) $(id).addEventListener('submit', (event) => {
  event.preventDefault(); const form = event.currentTarget;
  if (id === 'verify') $('verification').textContent = 'Verificando…';
  busy(form.querySelector('button'), async () => {
    const data = new FormData(form);
    for (const value of data.values()) if (value instanceof File && value.size > 10 * 1024 * 1024) throw new Error('Cada archivo debe tener como máximo 10 MB; el total de la petición no puede superar 12 MB.');
    try {
      const result = await (await api(`/api/${id}`, { method: 'POST', body: data })).json();
      if (id === 'sign') { download(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }), 'signature.json'); form.elements.password.value = ''; status('Firma creada y descargada.'); }
      else { $('verification').textContent = `Firma válida\nTitular: ${result.subject}\nSerie: ${result.serial}\nSHA-256: ${result.sha256}\nRevocación comprobada con la CA local.`; status('Integridad, vigencia y confianza verificadas.'); }
    } catch (error) { if (id === 'verify') $('verification').textContent = `Verificación fallida: ${error.message}`; throw error; }
  });
});
