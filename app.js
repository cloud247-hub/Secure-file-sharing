(() => {
  'use strict';
  const Core = window.Cloud247SecureFile;
  const Config = window.CLOUD247_SECURE_FILE_CONFIG || {};
  const $ = (id) => document.getElementById(id);
  const apiBase = String(Config.apiBase || '').replace(/\/+$/, '');
  const maxUploadBytes = Number(Config.maxUploadBytes) || (100 * 1024 * 1024);
  const state = {
    sourceFile: null,
    encryptedBlob: null,
    encryptedName: '',
    keyToken: '',
    packageFile: null,
    packageBytes: null,
    inspected: null,
    remote: { id: '', mode: '', key: '', expiresAt: '', oneTime: false, size: 0, bytes: null, download: null },
    apiOnline: false
  };
  let remoteCountdownTimer = null;

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return '–';
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KB', 'MB', 'GB'];
    let value = bytes / 1024, i = 0;
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
    return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[i]}`;
  }

  function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '–';
    return new Intl.DateTimeFormat('nb-NO', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }

  function expirationTime(value) {
    if (value === null || value === undefined || value === '') return NaN;
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric > 0) {
      return numeric < 1e12 ? numeric * 1000 : numeric;
    }
    const parsed = Date.parse(String(value));
    return Number.isFinite(parsed) ? parsed : NaN;
  }

  function formatRemaining(value) {
    const expiresAt = expirationTime(value);
    if (!Number.isFinite(expiresAt)) return '–';
    const remaining = Math.max(0, expiresAt - Date.now());
    if (remaining <= 0) return 'Utløpt';
    const totalSeconds = Math.ceil(remaining / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) return `${hours} t ${minutes} min ${seconds} sek`;
    if (minutes > 0) return `${minutes} min ${seconds} sek`;
    return `${seconds} sek`;
  }

  function stopRemoteCountdown() {
    if (remoteCountdownTimer) clearInterval(remoteCountdownTimer);
    remoteCountdownTimer = null;
  }

  function updateRemoteCountdown() {
    const el = $('remoteExpiresCountdown');
    if (!el) return;
    const text = formatRemaining(state.remote.expiresAt);
    el.textContent = text;
    el.classList.toggle('is-expired', text === 'Utløpt');
    if (text === 'Utløpt') {
      stopRemoteCountdown();
      if (!state.remote.download) $('fetchSharedFile').disabled = true;
      const pill = $('remoteAvailability');
      if (pill && !state.remote.download) {
        pill.textContent = 'Utløpt';
        pill.className = 'status-pill is-bad';
      }
    }
  }

  function startRemoteCountdown() {
    stopRemoteCountdown();
    updateRemoteCountdown();
    if (formatRemaining(state.remote.expiresAt) !== 'Utløpt' && Number.isFinite(expirationTime(state.remote.expiresAt))) {
      remoteCountdownTimer = setInterval(updateRemoteCountdown, 1000);
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  let toastTimer;
  function toast(message) {
    clearTimeout(toastTimer);
    const el = $('toast');
    el.textContent = message;
    el.classList.add('is-visible');
    toastTimer = setTimeout(() => el.classList.remove('is-visible'), 2600);
  }

  function switchTab(tab) {
    document.querySelectorAll('[data-tab]').forEach(btn => {
      const active = btn.dataset.tab === tab;
      btn.classList.toggle('is-active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    $('encryptPanel').hidden = tab !== 'encrypt';
    $('decryptPanel').hidden = tab !== 'decrypt';
  }

  function updateEncryptButton() {
    $('encryptButton').disabled = !(state.sourceFile && state.apiOnline);
  }

  function setEncryptFile(file) {
    state.sourceFile = file || null;
    $('encryptFileInput').value = '';
    $('encryptResult').hidden = true;
    if (!file) {
      $('encryptFileInfo').innerHTML = '<strong>Ingen fil valgt</strong><span>Dra en fil hit eller velg fra enheten.</span>';
      updateEncryptButton();
      return;
    }
    if (file.size > maxUploadBytes) {
      state.sourceFile = null;
      $('encryptFileInfo').innerHTML = `<strong>Filen er for stor</strong><span>Maks ${formatBytes(maxUploadBytes)} for nettdeling i denne installasjonen.</span>`;
      updateEncryptButton();
      return;
    }
    $('encryptFileInfo').innerHTML = `<strong>${escapeHtml(file.name)}</strong><span>${formatBytes(file.size)}${file.type ? ` · ${escapeHtml(file.type)}` : ''}</span>`;
    updateEncryptButton();
  }

  function bindDropZone(zoneId, inputId, setter) {
    const zone = $(zoneId), input = $(inputId);
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', () => setter(input.files?.[0] || null));
    ['dragenter','dragover'].forEach(type => zone.addEventListener(type, e => { e.preventDefault(); zone.classList.add('is-dragging'); }));
    ['dragleave','drop'].forEach(type => zone.addEventListener(type, e => { e.preventDefault(); zone.classList.remove('is-dragging'); }));
    zone.addEventListener('drop', e => setter(e.dataTransfer?.files?.[0] || null));
  }

  async function checkApi() {
    const el = $('apiStatus');
    if (!apiBase) {
      el.className = 'api-status is-error';
      el.innerHTML = '<span class="status-dot"></span><span>API er ikke konfigurert i config.js.</span>';
      state.apiOnline = false;
      updateEncryptButton();
      return;
    }
    try {
      const res = await fetch(`${apiBase}/api/health`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      state.apiOnline = data.ok === true;
      el.className = state.apiOnline ? 'api-status is-online' : 'api-status is-error';
      el.innerHTML = state.apiOnline
        ? `<span class="status-dot"></span><span>Filserver tilgjengelig · maks ${formatBytes(Math.min(Number(data.maxUploadBytes) || maxUploadBytes, maxUploadBytes))}</span>`
        : '<span class="status-dot"></span><span>Filserver svarer, men er ikke klar.</span>';
      $('apiBadge').textContent = state.apiOnline ? 'R2 tilgjengelig' : 'API-feil';
    } catch (err) {
      state.apiOnline = false;
      el.className = 'api-status is-error';
      el.innerHTML = '<span class="status-dot"></span><span>Kan ikke kontakte filserveren. Kontroller config.js og Worker.</span>';
      $('apiBadge').textContent = 'API frakoblet';
    }
    updateEncryptButton();
  }

  async function apiError(response) {
    try {
      const body = await response.json();
      return body.message || body.error || `HTTP ${response.status}`;
    } catch {
      return `HTTP ${response.status}`;
    }
  }

  async function uploadPackage(packageBytes, expiresIn, oneTime) {
    const response = await fetch(`${apiBase}/api/files`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Expires-In': String(expiresIn),
        'X-One-Time': oneTime ? '1' : '0'
      },
      body: new Blob([packageBytes], { type: 'application/octet-stream' })
    });
    if (!response.ok) throw new Error(await apiError(response));
    return response.json();
  }

  function buildShareLink(id, securityMode, keyToken, includeKey) {
    const url = new URL(location.href);
    url.search = '';
    const params = new URLSearchParams();
    params.set('file', id);
    params.set('mode', securityMode);
    if (securityMode === 'key' && includeKey) params.set('key', keyToken);
    url.hash = params.toString();
    return url.toString();
  }

  async function encryptAndUpload() {
    if (!state.sourceFile || !state.apiOnline) return;
    const selectedMode = 'key';
    const password = '';
    const button = $('encryptButton');
    button.disabled = true;
    button.textContent = 'Krypterer og laster opp…';
    try {
      const fileBytes = new Uint8Array(await state.sourceFile.arrayBuffer());
      const metadata = {
        name: state.sourceFile.name,
        type: state.sourceFile.type || 'application/octet-stream',
        size: state.sourceFile.size,
        lastModified: state.sourceFile.lastModified || 0
      };
      const encrypted = await Core.encryptPackage({ fileBytes, metadata, mode: selectedMode, password });
      const outputName = `${state.sourceFile.name}.c247`;
      state.encryptedBlob = new Blob([encrypted.packageBytes], { type: 'application/octet-stream' });
      state.encryptedName = outputName;
      state.keyToken = encrypted.keyToken;

      const upload = await uploadPackage(encrypted.packageBytes, Number($('expiresIn').value), $('oneTime').checked);
      const includeKey = selectedMode === 'key' && $('includeKeyInLink').checked;
      const shareLink = buildShareLink(upload.id, selectedMode, encrypted.keyToken, includeKey);
      const fingerprint = await Core.sha256Hex(encrypted.packageBytes);

      $('encryptResult').hidden = false;
      $('shareLink').value = shareLink;
      $('encryptedSummary').innerHTML = `<strong>${escapeHtml(outputName)}</strong><span>${formatBytes(encrypted.packageBytes.length)} · SHA-256 ${fingerprint.slice(0, 12)}…</span>`;
      $('shareMeta').innerHTML = `Utløper <strong>${escapeHtml(formatDate(upload.expiresAt))}</strong>${upload.oneTime ? ' · slettes ved første henting' : ''}`;
      if (selectedMode === 'key') {
        $('keyResultArea').hidden = false;
        $('generatedKey').value = encrypted.keyToken;
        $('keyShareHint').textContent = includeKey
          ? 'Nøkkelen er også lagt i URL-fragmentet i delingslenken.'
          : 'Nøkkelen er ikke i lenken. Send den i en separat kanal.';
      } else {
        $('keyResultArea').hidden = true;
      }
      $('encryptStatus').textContent = 'Filen er kryptert og lastet opp';
      toast('Filen er klar til deling.');
    } catch (err) {
      toast(err.message || 'Opplasting mislyktes.');
    } finally {
      button.textContent = 'Krypter og last opp';
      updateEncryptButton();
    }
  }

  function downloadBlob(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function copyValue(id, message) {
    const value = $(id).value;
    if (!value) return;
    try { await navigator.clipboard.writeText(value); }
    catch { $(id).select(); document.execCommand('copy'); }
    toast(message);
  }

  async function shareLinkNative() {
    const url = $('shareLink').value;
    if (!url) return;
    if (!navigator.share) return copyValue('shareLink', 'Delingslenken er kopiert.');
    try {
      await navigator.share({ title: 'Sikker fil fra Cloud247', text: 'Åpne den krypterte filen her:', url });
    } catch (err) {
      if (err?.name !== 'AbortError') toast('Kunne ikke åpne delingsmenyen.');
    }
  }

  function setPackageFile(file) {
    state.packageFile = file || null;
    state.packageBytes = null;
    state.inspected = null;
    $('decryptFileInput').value = '';
    $('decryptButton').disabled = true;
    $('decryptResult').hidden = true;
    $('decryptModeInfo').hidden = true;
    if (!file) {
      $('decryptFileInfo').innerHTML = '<strong>Ingen kryptert fil valgt</strong><span>Velg en lokal .c247-fil.</span>';
      return;
    }
    $('decryptFileInfo').innerHTML = `<strong>${escapeHtml(file.name)}</strong><span>${formatBytes(file.size)}</span>`;
    inspectSelectedPackage(file);
  }

  async function inspectSelectedPackage(file) {
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const inspected = Core.inspectPackage(bytes);
      state.packageBytes = bytes;
      state.inspected = inspected;
      $('decryptModeInfo').hidden = false;
      $('decryptModeInfo').innerHTML = inspected.header.mode === 'key'
        ? '<strong>Nøkkelbeskyttet fil</strong><span>Lim inn Cloud247-nøkkelen.</span>'
        : `<strong>Passordbeskyttet fil</strong><span>PBKDF2-SHA256 · ${Number(inspected.header.iterations).toLocaleString('nb-NO')} iterasjoner</span>`;
      $('decryptKeyGroup').hidden = inspected.header.mode !== 'key';
      $('decryptPasswordGroup').hidden = inspected.header.mode !== 'password';
      $('decryptButton').disabled = false;
    } catch (err) {
      $('decryptModeInfo').hidden = false;
      $('decryptModeInfo').innerHTML = `<strong>Kan ikke åpne filen</strong><span>${escapeHtml(err.message)}</span>`;
    }
  }

  async function decryptLocal() {
    if (!state.packageBytes || !state.inspected) return;
    const button = $('decryptButton');
    button.disabled = true; button.textContent = 'Åpner…';
    try {
      const result = await Core.decryptPackage({ packageBytes: state.packageBytes, keyToken: $('decryptKey').value.trim(), password: $('decryptPassword').value });
      const blob = new Blob([result.fileBytes], { type: result.metadata.type || 'application/octet-stream' });
      $('decryptResult').hidden = false;
      $('decryptedSummary').innerHTML = `<strong>${escapeHtml(result.metadata.name || 'dekryptert-fil')}</strong><span>${formatBytes(result.fileBytes.length)}${result.metadata.type ? ` · ${escapeHtml(result.metadata.type)}` : ''}</span>`;
      $('downloadDecrypted').onclick = () => downloadBlob(blob, result.metadata.name || 'dekryptert-fil');
      toast('Filen er åpnet.');
    } catch (err) { $('decryptResult').hidden = true; toast(err.message || 'Dekrypteringen mislyktes.'); }
    finally { button.disabled = false; button.textContent = 'Åpne lokal fil'; }
  }

  function parseRemoteHeaders(response) {
    return {
      expiresAt: response.headers.get('X-Cloud247-Expires-At') || '',
      oneTime: response.headers.get('X-Cloud247-One-Time') === '1',
      size: Number(response.headers.get('Content-Length')) || 0
    };
  }

  function renderRemoteMeta() {
    const meta = state.remote;
    $('remoteMeta').innerHTML = `
      <div><span>Utløper</span><strong id="remoteExpiresCountdown">${escapeHtml(formatRemaining(meta.expiresAt))}</strong></div>
      <div><span>Sletting</span><strong>${escapeHtml(meta.oneTime ? 'Ved første henting' : 'Ved utløp')}</strong></div>
      <div><span>Kryptert størrelse</span><strong>${escapeHtml(meta.size ? formatBytes(meta.size) : '–')}</strong></div>
      <div><span>Beskyttelse</span><strong>Generert nøkkel</strong></div>`;
    startRemoteCountdown();
  }

  async function inspectRemoteShare() {
    if (!state.remote.id || !apiBase) return;
    const pill = $('remoteAvailability');
    pill.textContent = 'Kontrollerer…'; pill.className = 'status-pill';
    try {
      const res = await fetch(`${apiBase}/api/files/${encodeURIComponent(state.remote.id)}`, { method: 'HEAD', cache: 'no-store' });
      if (!res.ok) throw new Error(await apiError(res));
      Object.assign(state.remote, parseRemoteHeaders(res));
      pill.textContent = 'Tilgjengelig'; pill.className = 'status-pill is-good';
      $('fetchSharedFile').disabled = false;
      renderRemoteMeta();
    } catch (err) {
      pill.textContent = 'Ikke tilgjengelig'; pill.className = 'status-pill is-bad';
      $('fetchSharedFile').disabled = true;
      $('remoteMeta').innerHTML = `<div><span>Status</span><strong>${escapeHtml(err.message || 'Filen finnes ikke')}</strong></div>`;
    }
  }

  async function fetchAndOpenRemote() {
    const { id } = state.remote;
    if (!id) return;
    const key = $('remoteKey').value.trim();
    if (!key) return toast('Skriv inn åpningsnøkkelen.');
    const button = $('fetchSharedFile');
    button.disabled = true; button.textContent = 'Henter og åpner…';
    try {
      let bytes = state.remote.bytes;
      if (!bytes) {
        const response = await fetch(`${apiBase}/api/files/${encodeURIComponent(id)}`, { cache: 'no-store' });
        if (!response.ok) throw new Error(await apiError(response));
        Object.assign(state.remote, parseRemoteHeaders(response));
        bytes = new Uint8Array(await response.arrayBuffer());
        state.remote.bytes = bytes;
      }
      const result = await Core.decryptPackage({ packageBytes: bytes, keyToken: key, password: '' });
      const blob = new Blob([result.fileBytes], { type: result.metadata.type || 'application/octet-stream' });
      state.remote.download = { blob, name: result.metadata.name || 'dekryptert-fil' };
      $('remoteResult').hidden = false;
      $('remoteDecryptedSummary').innerHTML = `<strong>${escapeHtml(state.remote.download.name)}</strong><span>${formatBytes(result.fileBytes.length)}${result.metadata.type ? ` · ${escapeHtml(result.metadata.type)}` : ''}</span>`;
      $('remoteAvailability').textContent = state.remote.oneTime ? 'Hentet og slettet' : 'Hentet';
      $('remoteAvailability').className = 'status-pill is-good';
      toast('Filen er dekryptert lokalt.');
    } catch (err) {
      $('remoteResult').hidden = true;
      toast(err.message || 'Kunne ikke hente eller åpne filen.');
      button.disabled = false;
    } finally {
      button.textContent = 'Hent og åpne fil';
      if (!state.remote.download) button.disabled = false;
    }
  }

  function loadRemoteFromFragment() {
    const raw = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
    const params = new URLSearchParams(raw);
    const id = params.get('file');
    if (!id) return;
    state.remote.id = id;
    state.remote.mode = 'key';
    state.remote.key = params.get('key') || '';
    $('remoteShare').hidden = false;
    $('remoteFileId').textContent = id;
    $('remoteKeyGroup').hidden = false;
    $('remoteKey').value = state.remote.key;
    switchTab('decrypt');
    inspectRemoteShare();
  }

  document.querySelectorAll('[data-tab]').forEach(btn => btn.addEventListener('click', () => switchTab(btn.dataset.tab)));
  bindDropZone('encryptDropZone', 'encryptFileInput', setEncryptFile);
  bindDropZone('decryptDropZone', 'decryptFileInput', setPackageFile);
  $('encryptButton').addEventListener('click', encryptAndUpload);
  $('copyLink').addEventListener('click', () => copyValue('shareLink', 'Delingslenken er kopiert.'));
  $('copyKey').addEventListener('click', () => copyValue('generatedKey', 'Nøkkelen er kopiert.'));
  $('shareLinkButton').addEventListener('click', shareLinkNative);
  $('downloadEncrypted').addEventListener('click', () => state.encryptedBlob && downloadBlob(state.encryptedBlob, state.encryptedName));
  $('decryptButton').addEventListener('click', decryptLocal);
  $('fetchSharedFile').addEventListener('click', fetchAndOpenRemote);
  $('downloadRemoteDecrypted').addEventListener('click', () => state.remote.download && downloadBlob(state.remote.download.blob, state.remote.download.name));
  $('year').textContent = new Date().getFullYear();
  loadRemoteFromFragment();
  checkApi();
})();
