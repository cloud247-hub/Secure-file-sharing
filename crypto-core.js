(function (root) {
  'use strict';

  const MAGIC = 'C247SF01';
  const VERSION = 1;
  const DEFAULT_ITERATIONS = 600000;
  const MAX_FILE_SIZE = 250 * 1024 * 1024;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function cryptoApi() {
    const c = root.crypto;
    if (!c || !c.subtle || !c.getRandomValues) {
      throw new Error('Nettleseren støtter ikke Web Crypto API.');
    }
    return c;
  }

  function bytesToBase64Url(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    const b64 = typeof btoa === 'function'
      ? btoa(binary)
      : Buffer.from(binary, 'binary').toString('base64');
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function base64UrlToBytes(value) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const binary = typeof atob === 'function'
      ? atob(padded)
      : Buffer.from(padded, 'base64').toString('binary');
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  function randomBytes(length) {
    const out = new Uint8Array(length);
    cryptoApi().getRandomValues(out);
    return out;
  }

  function writeU32(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    return out;
  }

  function readU32(bytes, offset) {
    return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
  }

  function concatBytes(...parts) {
    const size = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(size);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function makeKeyToken(rawKey) {
    return `c247_${bytesToBase64Url(rawKey)}`;
  }

  function parseKeyToken(token) {
    const value = String(token || '').trim();
    if (!value.startsWith('c247_')) throw new Error('Nøkkelen har ugyldig format.');
    const raw = base64UrlToBytes(value.slice(5));
    if (raw.length !== 32) throw new Error('Nøkkelen har ugyldig lengde.');
    return raw;
  }

  async function importAesKey(rawKey) {
    return cryptoApi().subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function derivePasswordKey(password, salt, iterations) {
    if (!password) throw new Error('Skriv inn passordet.');
    const material = await cryptoApi().subtle.importKey(
      'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return cryptoApi().subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  function encodePayload(fileBytes, metadata) {
    const metaBytes = encoder.encode(JSON.stringify(metadata));
    return concatBytes(writeU32(metaBytes.length), metaBytes, fileBytes);
  }

  function decodePayload(payload) {
    if (payload.length < 4) throw new Error('Den dekrypterte filen er ugyldig.');
    const metaLength = readU32(payload, 0);
    if (metaLength < 2 || metaLength > payload.length - 4) throw new Error('Metadata i filen er ugyldig.');
    let metadata;
    try {
      metadata = JSON.parse(decoder.decode(payload.subarray(4, 4 + metaLength)));
    } catch {
      throw new Error('Metadata i filen kunne ikke leses.');
    }
    return { metadata, fileBytes: payload.subarray(4 + metaLength) };
  }

  function inspectPackage(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    const minSize = MAGIC.length + 4 + 2 + 16;
    if (bytes.length < minSize) throw new Error('Filen er for liten til å være en Cloud247 Secure File.');
    const magic = decoder.decode(bytes.subarray(0, MAGIC.length));
    if (magic !== MAGIC) throw new Error('Dette er ikke en Cloud247 Secure File (.c247).');
    const headerLength = readU32(bytes, MAGIC.length);
    const headerStart = MAGIC.length + 4;
    const headerEnd = headerStart + headerLength;
    if (headerLength < 2 || headerEnd >= bytes.length) throw new Error('Den krypterte filen har ugyldig header.');
    const headerBytes = bytes.subarray(headerStart, headerEnd);
    let header;
    try {
      header = JSON.parse(decoder.decode(headerBytes));
    } catch {
      throw new Error('Headeren i den krypterte filen kunne ikke leses.');
    }
    if (header.v !== VERSION || header.alg !== 'AES-GCM') throw new Error('Denne filversjonen støttes ikke.');
    if (!['key', 'password'].includes(header.mode)) throw new Error('Ukjent sikkerhetsmodus i filen.');
    const iv = base64UrlToBytes(header.iv || '');
    if (iv.length !== 12) throw new Error('Den krypterte filen har ugyldig IV.');
    return {
      header,
      headerBytes,
      ciphertext: bytes.subarray(headerEnd)
    };
  }

  async function encryptPackage({ fileBytes, metadata, mode = 'key', password = '' }) {
    if (!(fileBytes instanceof Uint8Array)) fileBytes = new Uint8Array(fileBytes);
    if (fileBytes.length > MAX_FILE_SIZE) throw new Error('Filen er større enn 250 MB-grensen i denne nettleserversjonen.');
    if (!['key', 'password'].includes(mode)) throw new Error('Ugyldig sikkerhetsmodus.');

    const iv = randomBytes(12);
    let key;
    let keyToken = '';
    const header = {
      v: VERSION,
      alg: 'AES-GCM',
      mode,
      iv: bytesToBase64Url(iv),
      created: new Date().toISOString()
    };

    if (mode === 'key') {
      const rawKey = randomBytes(32);
      keyToken = makeKeyToken(rawKey);
      key = await importAesKey(rawKey);
    } else {
      const salt = randomBytes(16);
      header.kdf = 'PBKDF2-SHA256';
      header.salt = bytesToBase64Url(salt);
      header.iterations = DEFAULT_ITERATIONS;
      key = await derivePasswordKey(password, salt, DEFAULT_ITERATIONS);
    }

    const headerBytes = encoder.encode(JSON.stringify(header));
    const payload = encodePayload(fileBytes, metadata);
    const ciphertext = new Uint8Array(await cryptoApi().subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: headerBytes, tagLength: 128 },
      key,
      payload
    ));
    const packageBytes = concatBytes(encoder.encode(MAGIC), writeU32(headerBytes.length), headerBytes, ciphertext);
    return { packageBytes, keyToken, header };
  }

  async function decryptPackage({ packageBytes, keyToken = '', password = '' }) {
    const inspected = inspectPackage(packageBytes);
    const { header, headerBytes, ciphertext } = inspected;
    const iv = base64UrlToBytes(header.iv);
    let key;
    if (header.mode === 'key') {
      key = await importAesKey(parseKeyToken(keyToken));
    } else {
      const salt = base64UrlToBytes(header.salt || '');
      if (salt.length < 16) throw new Error('Salt i filen er ugyldig.');
      const iterations = Number(header.iterations);
      if (!Number.isFinite(iterations) || iterations < 100000 || iterations > 5000000) {
        throw new Error('PBKDF2-innstillingene i filen er ugyldige.');
      }
      key = await derivePasswordKey(password, salt, iterations);
    }
    let plaintext;
    try {
      plaintext = new Uint8Array(await cryptoApi().subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: headerBytes, tagLength: 128 },
        key,
        ciphertext
      ));
    } catch {
      throw new Error(header.mode === 'key'
        ? 'Kunne ikke dekryptere. Kontroller at du bruker riktig nøkkel.'
        : 'Kunne ikke dekryptere. Kontroller passordet og filen.');
    }
    const decoded = decodePayload(plaintext);
    return { ...decoded, header };
  }

  async function sha256Hex(bytes) {
    const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = new Uint8Array(await cryptoApi().subtle.digest('SHA-256', data));
    return Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
  }

  const api = {
    MAGIC, VERSION, DEFAULT_ITERATIONS, MAX_FILE_SIZE,
    bytesToBase64Url, base64UrlToBytes, makeKeyToken, parseKeyToken,
    inspectPackage, encryptPackage, decryptPackage, sha256Hex
  };

  root.Cloud247SecureFile = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
