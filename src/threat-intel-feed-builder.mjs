import crypto from 'node:crypto';
import { validateDefinitions } from './definition-security.mjs';

const SHA256 = /^[0-9a-f]{64}$/i;
const MALWAREBAZAAR_ENDPOINT = 'https://mb-api.abuse.ch/api/v1/';
const THREATFOX_ENDPOINT = 'https://threatfox-api.abuse.ch/api/v1/';
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_REMOTE_RECORDS = 100_000;
const MAX_THREAT_INTEL_ENTRIES = 250_000;
const DEFAULT_RETENTION_DAYS = 180;
const MAX_RETENTION_DAYS = 366;

/**
 * Fetches only metadata from MalwareBazaar. Samples are never uploaded or
 * downloaded; the Auth-Key is intended to be used by the GitHub Action only.
 */
export async function fetchMalwareBazaar({
  authKey,
  hours = 168,
  fetchImpl = globalThis.fetch,
  timeoutMs = 30_000
} = {}) {
  const key = requireAuthKey(authKey);
  const lookbackHours = clampInteger(hours, 1, 168, 168);
  return requestJson(MALWAREBAZAAR_ENDPOINT, {
    method: 'POST',
    headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({ query: 'recent_detections', hours: String(lookbackHours) }).toString()
  }, { fetchImpl, timeoutMs });
}

/** Fetches recent ThreatFox IOCs and keeps only exact SHA-256 sample hashes. */
export async function fetchThreatFox({
  authKey,
  days = 7,
  fetchImpl = globalThis.fetch,
  timeoutMs = 30_000
} = {}) {
  const key = requireAuthKey(authKey);
  const lookbackDays = clampInteger(days, 1, 7, 7);
  return requestJson(THREATFOX_ENDPOINT, {
    method: 'POST',
    headers: { 'Auth-Key': key, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ query: 'get_iocs', days: lookbackDays })
  }, { fetchImpl, timeoutMs });
}

/**
 * Builds the compact definition document consumed by the existing signed
 * definition updater. Remote exact hashes are deliberately kept separate in
 * `threatIntel` so the UI can later show provider, family and expiry details.
 */
export function buildThreatIntelDefinitions({
  baseDefinitions,
  previousDefinitions = null,
  malwareBazaarPayload = null,
  threatFoxPayload = null,
  sourceStatus = {},
  generatedAt = new Date().toISOString(),
  version,
  retentionDays = DEFAULT_RETENTION_DAYS
} = {}) {
  const base = validateDefinitions(structuredClone(baseDefinitions));
  const previous = previousDefinitions ? validateDefinitions(structuredClone(previousDefinitions)) : null;
  const now = parseDate(generatedAt) ?? new Date();
  const retention = clampInteger(retentionDays, 1, MAX_RETENTION_DAYS, DEFAULT_RETENTION_DAYS);
  const entries = new Map();

  for (const [hash, value] of Object.entries(previous?.threatIntel?.entries ?? {})) {
    if (!SHA256.test(hash) || !value || typeof value !== 'object') continue;
    const normalized = normalizeThreatEntry(hash, value, now, retention);
    if (normalized) entries.set(hash.toLowerCase(), normalized);
  }

  for (const record of normalizeMalwareBazaar(malwareBazaarPayload, now, retention)) mergeEntry(entries, record);
  for (const record of normalizeThreatFox(threatFoxPayload, now, retention)) mergeEntry(entries, record);

  for (const [hash, value] of entries) {
    if (parseDate(value.expiresAt)?.getTime() <= now.getTime()) entries.delete(hash);
  }
  if (entries.size > MAX_THREAT_INTEL_ENTRIES) {
    const retained = [...entries.entries()]
      .sort((left, right) => dateValue(right[1].lastSeen || right[1].firstSeen) - dateValue(left[1].lastSeen || left[1].firstSeen))
      .slice(0, MAX_THREAT_INTEL_ENTRIES);
    entries.clear();
    for (const [hash, value] of retained) entries.set(hash, value);
  }

  const sha256 = { ...base.sha256 };
  for (const [hash, entry] of entries) {
    const intelDescription = renderDescription(entry);
    const existing = sha256[hash];
    if (!existing) sha256[hash] = intelDescription;
    else if (!toDescriptionList(existing).some(value => value === intelDescription)) sha256[hash] = [...toDescriptionList(existing), intelDescription].slice(0, 8);
  }

  const nextVersion = Number.isSafeInteger(version) && version >= 1
    ? version
    : previous
      ? Math.max(base.version + 1, previous.version + 1)
      : Math.max(base.version + 1, Math.floor(now.getTime() / 1_000));
  const definitions = {
    version: nextVersion,
    generatedAt: now.toISOString(),
    sha256,
    puaSha256: structuredClone(base.puaSha256 ?? {}),
    patterns: structuredClone(base.patterns),
    threatIntel: {
      schemaVersion: 1,
      generatedAt: now.toISOString(),
      retentionDays: retention,
      sources: normalizeSourceStatus(sourceStatus, now),
      entries: Object.fromEntries(entries)
    }
  };
  return validateDefinitions(definitions);
}

export function normalizeMalwareBazaar(payload, now = new Date(), retentionDays = DEFAULT_RETENTION_DAYS) {
  const records = Array.isArray(payload?.data) ? payload.data.slice(0, MAX_REMOTE_RECORDS) : [];
  return records.map(record => {
    const hash = normalizeHash(record?.sha256_hash ?? record?.sha256Hash);
    if (!hash) return null;
    const firstSeen = normalizeSourceDate(record?.first_seen);
    const lastSeen = normalizeSourceDate(record?.last_seen) ?? firstSeen;
    const anchor = parseDate(lastSeen ?? firstSeen) ?? now;
    return {
      hash,
      providers: ['malwarebazaar'],
      confidence: 100,
      families: cleanList([record?.signature], 160, 8),
      tags: cleanList(record?.tags, 80, 16),
      firstSeen,
      lastSeen,
      expiresAt: new Date(anchor.getTime() + retentionDays * 24 * 60 * 60 * 1_000).toISOString(),
      references: [`https://bazaar.abuse.ch/sample/${hash}/`]
    };
  }).filter(Boolean);
}

export function normalizeThreatFox(payload, now = new Date(), retentionDays = DEFAULT_RETENTION_DAYS) {
  const records = Array.isArray(payload?.data) ? payload.data.slice(0, MAX_REMOTE_RECORDS) : [];
  const output = [];
  for (const record of records) {
    const confidence = clampNumber(record?.confidence_level, 0, 100, 0);
    const firstSeen = normalizeSourceDate(record?.first_seen);
    const lastSeen = normalizeSourceDate(record?.last_seen) ?? firstSeen;
    const anchor = parseDate(lastSeen ?? firstSeen) ?? now;
    const common = {
      providers: ['threatfox'],
      confidence,
      families: cleanList([record?.malware_printable, record?.malware], 160, 8),
      tags: cleanList(record?.tags, 80, 16),
      firstSeen,
      lastSeen,
      expiresAt: new Date(anchor.getTime() + retentionDays * 24 * 60 * 60 * 1_000).toISOString(),
      references: cleanList([record?.reference], 500, 4)
    };
    const sampleHashes = Array.isArray(record?.malware_samples)
      ? record.malware_samples.map(sample => normalizeHash(sample?.sha256_hash ?? sample?.sha256Hash)).filter(Boolean)
      : [];
    const directHash = confidence >= 75
      ? normalizeHash(record?.sha256_hash ?? record?.sha256Hash ?? (isSha256Ioc(record) ? record?.ioc : null))
      : null;
    const hashes = [...new Set([...sampleHashes, directHash].filter(Boolean))];
    for (const hash of hashes) output.push({ hash, ...common });
  }
  return output;
}

export function createSignedDefinitionEnvelope(definitions, { keyId, privateKey }) {
  const validated = validateDefinitions(structuredClone(definitions));
  if (typeof keyId !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(keyId)) throw new Error('El keyId de definiciones no es válido.');
  const signingKey = privateKey?.type === 'private' ? privateKey : crypto.createPrivateKey(privateKey);
  if (signingKey.asymmetricKeyType !== 'ed25519') throw new Error('La clave de definiciones debe ser Ed25519.');
  const payload = Buffer.from(JSON.stringify(validated));
  return {
    schemaVersion: 1,
    keyId,
    payloadBase64: payload.toString('base64'),
    signatureBase64: crypto.sign(null, payload, signingKey).toString('base64')
  };
}

async function requestJson(url, options, { fetchImpl = globalThis.fetch, timeoutMs = 30_000 } = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('No hay transporte HTTP disponible.');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), clampInteger(timeoutMs, 2_000, 120_000, 30_000));
  try {
    const response = await fetchImpl(url, { ...options, signal: controller.signal });
    if (!response?.ok) throw new Error(`Proveedor HTTP ${Number(response?.status) || 0}.`);
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw new Error('La respuesta del proveedor supera el límite permitido.');
    try { return JSON.parse(text); }
    catch { throw new Error('El proveedor no devolvió JSON válido.'); }
  } finally {
    clearTimeout(timeout);
  }
}

function mergeEntry(entries, incoming) {
  if (!incoming?.hash) return;
  const existing = entries.get(incoming.hash);
  if (!existing) {
    entries.set(incoming.hash, normalizeThreatEntry(incoming.hash, incoming, new Date(incoming.expiresAt), 1) ?? incoming);
    return;
  }
  existing.providers = uniqueList([...existing.providers, ...incoming.providers], 8);
  existing.families = uniqueList([...existing.families, ...incoming.families], 16);
  existing.tags = uniqueList([...existing.tags, ...incoming.tags], 16);
  existing.references = uniqueList([...existing.references, ...incoming.references], 4);
  existing.confidence = Math.max(existing.confidence, incoming.confidence);
  existing.firstSeen = earliestDate(existing.firstSeen, incoming.firstSeen);
  existing.lastSeen = latestDate(existing.lastSeen, incoming.lastSeen);
  existing.expiresAt = latestDate(existing.expiresAt, incoming.expiresAt);
}

function normalizeThreatEntry(hash, value, now, retentionDays) {
  if (!SHA256.test(hash)) return null;
  const firstSeen = normalizeSourceDate(value.firstSeen);
  const lastSeen = normalizeSourceDate(value.lastSeen) ?? firstSeen;
  const expiresAt = normalizeSourceDate(value.expiresAt) ?? new Date((parseDate(lastSeen) ?? now).getTime() + retentionDays * 24 * 60 * 60 * 1_000).toISOString();
  return {
    providers: uniqueList(cleanList(value.providers, 40, 8), 8),
    confidence: clampNumber(value.confidence, 0, 100, 0),
    families: uniqueList(cleanList(value.families, 160, 16), 16),
    tags: uniqueList(cleanList(value.tags, 80, 16), 16),
    firstSeen,
    lastSeen,
    expiresAt,
    references: uniqueList(cleanList(value.references, 500, 4), 4)
  };
}

function normalizeSourceStatus(value, now) {
  const input = value && typeof value === 'object' ? value : {};
  return Object.fromEntries(Object.entries(input).slice(0, 8).map(([provider, status]) => [provider.slice(0, 40), {
    status: ['ok', 'error', 'not-configured', 'not-found'].includes(status?.status) ? status.status : 'unknown',
    queriedAt: normalizeSourceDate(status?.queriedAt) ?? now.toISOString(),
    records: clampInteger(status?.records, 0, MAX_REMOTE_RECORDS, 0),
    error: typeof status?.error === 'string' ? status.error.slice(0, 240) : null
  }]));
}

function renderDescription(entry) {
  const providers = entry.providers.map(provider => provider === 'malwarebazaar' ? 'MalwareBazaar' : provider === 'threatfox' ? 'ThreatFox' : provider).join(' + ');
  const family = entry.families[0] ? ` (${entry.families[0]})` : '';
  return `Threat intelligence: known malicious — ${providers}${family}`.slice(0, 500);
}

function toDescriptionList(value) { return Array.isArray(value) ? value.filter(item => typeof item === 'string') : typeof value === 'string' ? [value] : []; }
function normalizeHash(value) { const hash = typeof value === 'string' ? value.trim().toLowerCase() : ''; return SHA256.test(hash) ? hash : null; }
function isSha256Ioc(record) { return typeof record?.ioc_type === 'string' && /sha256/i.test(record.ioc_type); }
function requireAuthKey(value) { const key = typeof value === 'string' ? value.trim() : ''; if (!key || key.length > 512) throw new Error('Falta un Auth-Key de abuse.ch válido.'); return key; }
function normalizeSourceDate(value) { const date = parseDate(value); return date ? date.toISOString() : null; }
function parseDate(value) {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value;
  if (typeof value !== 'string' || !value.trim()) return null;
  const text = value.trim().replace(/\s+UTC$/i, 'Z').replace(/^([0-9]{4}-[0-9]{2}-[0-9]{2})\s+([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\s+Z)?$/, '$1T$2Z');
  const timestamp = Date.parse(text);
  return Number.isFinite(timestamp) ? new Date(timestamp) : null;
}
function dateValue(value) { return parseDate(value)?.getTime() ?? 0; }
function earliestDate(left, right) { if (!left) return right ?? null; if (!right) return left; return dateValue(left) <= dateValue(right) ? left : right; }
function latestDate(left, right) { if (!left) return right ?? null; if (!right) return left; return dateValue(left) >= dateValue(right) ? left : right; }
function cleanList(value, maximum, limit) { const values = Array.isArray(value) ? value : [value]; return values.map(item => typeof item === 'string' ? item.trim().slice(0, maximum) : '').filter(Boolean).slice(0, limit); }
function uniqueList(values, limit) { return [...new Set(values.filter(Boolean))].slice(0, limit); }
function clampNumber(value, minimum, maximum, fallback) { return Number.isFinite(Number(value)) ? Math.max(minimum, Math.min(maximum, Number(value))) : fallback; }
function clampInteger(value, minimum, maximum, fallback) { return Number.isSafeInteger(Number(value)) ? Math.max(minimum, Math.min(maximum, Number(value))) : fallback; }
