import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';

const STORE_SCHEMA_VERSION = 1;
const MAX_ENTRIES = 10_000;
const MAX_SOURCES = 8;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_RATE_LIMIT = 6;
const SHA256 = /^[0-9a-f]{64}$/i;

const CIRCL_ENDPOINT = 'https://hashlookup.circl.lu';
const MALWAREBAZAAR_ENDPOINT = 'https://mb-api.abuse.ch/api/v1/';
const THREATFOX_ENDPOINT = 'https://threatfox-api.abuse.ch/api/v1/';

/**
 * Small, privacy-preserving reputation cache.
 *
 * The store never uploads a file. A lookup sends only an exact SHA-256 and
 * keeps a bounded, expiring copy of the normalized answer on disk. Network
 * access is explicit (`allowNetwork: true`) so callers can connect it to the
 * existing reputation-sharing consent instead of silently changing privacy
 * behaviour during scans.
 */
export class ThreatIntelStore {
  constructor({
    dataDirectory,
    fetchImpl = globalThis.fetch,
    clock = () => new Date(),
    ttlMs = DEFAULT_TTL_MS,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxEntries = MAX_ENTRIES,
    maxRequestsPerMinute = DEFAULT_RATE_LIMIT,
    config = {},
    abuseChAuthKey = process.env.AEGIS_ABUSECH_AUTH_KEY
  } = {}) {
    if (!dataDirectory) throw new TypeError('Threat intelligence data directory is required');
    this.dataDirectory = path.resolve(dataDirectory);
    this.directory = path.join(this.dataDirectory, 'threat-intel');
    this.statePath = path.join(this.directory, 'cache.json');
    this.fetchImpl = typeof fetchImpl === 'function' ? fetchImpl : null;
    this.clock = clock;
    this.ttlMs = clampInteger(ttlMs, 60_000, 30 * 24 * 60 * 60 * 1_000, DEFAULT_TTL_MS);
    this.timeoutMs = clampInteger(timeoutMs, 1_000, 30_000, DEFAULT_TIMEOUT_MS);
    this.maxEntries = clampInteger(maxEntries, 100, MAX_ENTRIES, MAX_ENTRIES);
    this.maxRequestsPerMinute = clampInteger(maxRequestsPerMinute, 1, 60, DEFAULT_RATE_LIMIT);
    this.authKey = typeof abuseChAuthKey === 'string' && abuseChAuthKey.trim().length <= 512 ? abuseChAuthKey.trim() : '';
    this.providerConfig = {
      circl: { enabled: config?.circl?.enabled !== false },
      malwareBazaar: { enabled: config?.malwareBazaar?.enabled === true },
      threatFox: { enabled: config?.threatFox?.enabled === true }
    };
    this.entries = new Map();
    this.requestTimes = new Map();
    this.lastLookupAt = null;
    this.initialized = false;
  }

  async init() {
    await fsp.mkdir(this.directory, { recursive: true });
    const state = await readJsonOr(this.statePath, {});
    this.entries = new Map(Object.entries(sanitizeState(state).entries));
    this.initialized = true;
    return this.status();
  }

  status() {
    return {
      schemaVersion: STORE_SCHEMA_VERSION,
      cacheEntries: this.entries.size,
      cacheMaxEntries: this.maxEntries,
      ttlMs: this.ttlMs,
      lastLookupAt: this.lastLookupAt,
      providers: {
        circl: { enabled: this.providerConfig.circl.enabled, configured: this.providerConfig.circl.enabled, requiresKey: false },
        malwareBazaar: { enabled: this.providerConfig.malwareBazaar.enabled, configured: this.providerConfig.malwareBazaar.enabled && Boolean(this.authKey), requiresKey: true },
        threatFox: { enabled: this.providerConfig.threatFox.enabled, configured: this.providerConfig.threatFox.enabled && Boolean(this.authKey), requiresKey: true }
      },
      networkEnabled: false,
      fileUploadEnabled: false
    };
  }

  async lookupSha256(value, { allowNetwork = false, force = false } = {}) {
    this.ensureInitialized();
    const sha256 = normalizeHash(value);
    const now = this.clock();
    const cached = this.entries.get(sha256);
    if (!force && cached && Date.parse(cached.expiresAt) > now.getTime()) return structuredClone(cached);
    if (!allowNetwork) {
      return unavailableResult(sha256, 'network-consent-required', now);
    }
    if (!this.fetchImpl) return unavailableResult(sha256, 'network-unavailable', now);

    const sources = [];
    const providerCalls = [
      ['circl', this.providerConfig.circl.enabled, () => this.lookupCircl(sha256)],
      ['malwarebazaar', this.providerConfig.malwareBazaar.enabled && Boolean(this.authKey), () => this.lookupMalwareBazaar(sha256)],
      ['threatfox', this.providerConfig.threatFox.enabled && Boolean(this.authKey), () => this.lookupThreatFox(sha256)]
    ];
    for (const [provider, enabled, call] of providerCalls) {
      if (!enabled) {
        sources.push({ provider, status: provider === 'circl' ? 'disabled' : 'not-configured' });
        continue;
      }
      if (!this.takeRateSlot(provider, now.getTime())) {
        sources.push({ provider, status: 'rate-limited' });
        continue;
      }
      try {
        sources.push(await call());
      } catch (error) {
        sources.push({ provider, status: 'error', error: clampText(error?.message, 240) });
      }
    }

    const result = aggregateResult(sha256, sources, now, this.ttlMs);
    this.entries.delete(sha256);
    this.entries.set(sha256, result);
    while (this.entries.size > this.maxEntries) this.entries.delete(this.entries.keys().next().value);
    this.lastLookupAt = now.toISOString();
    await this.persist();
    return structuredClone(result);
  }

  async lookupCircl(sha256) {
    const response = await this.requestJson(`${CIRCL_ENDPOINT}/lookup/sha256/${sha256}`);
    if (response.notFound) return { provider: 'circl', status: 'not-found' };
    const body = response.body;
    return {
      provider: 'circl',
      status: 'match',
      kind: 'known-file-context',
      trust: clampNumber(body?.['hashlookup:trust'] ?? body?.trust, 0, 100, 50),
      source: clampText(body?.source ?? body?.db, 120),
      fileName: clampText(body?.FileName ?? body?.filename, 240),
      fileSize: clampInteger(body?.FileSize ?? body?.filesize, 0, Number.MAX_SAFE_INTEGER, null)
    };
  }

  async lookupMalwareBazaar(sha256) {
    const response = await this.requestForm(MALWAREBAZAAR_ENDPOINT, { query: 'get_info', hash: sha256 }, { 'Auth-Key': this.authKey });
    const data = Array.isArray(response.body?.data) ? response.body.data : [];
    if (!data.length || response.body?.query_status === 'no_results') return { provider: 'malwarebazaar', status: 'not-found' };
    const item = data[0] ?? {};
    return {
      provider: 'malwarebazaar',
      status: 'match',
      kind: 'known-malicious',
      signature: clampText(item.signature, 240),
      fileType: clampText(item.file_type ?? item.file_type_mime, 120),
      firstSeen: clampText(item.first_seen, 40),
      tags: Array.isArray(item.tags) ? item.tags.slice(0, 16).map(tag => clampText(tag, 80)).filter(Boolean) : []
    };
  }

  async lookupThreatFox(sha256) {
    const response = await this.requestJson(THREATFOX_ENDPOINT, {
      method: 'POST',
      headers: { 'Auth-Key': this.authKey, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ query: 'search_hash', hash: sha256 })
    });
    const data = Array.isArray(response.body?.data) ? response.body.data : [];
    if (!data.length || response.body?.query_status === 'no_result') return { provider: 'threatfox', status: 'not-found' };
    const families = [...new Set(data.slice(0, 16).map(item => clampText(item?.malware_printable ?? item?.malware, 160)).filter(Boolean))];
    return {
      provider: 'threatfox',
      status: 'match',
      kind: 'known-malicious',
      confidence: Math.max(...data.slice(0, 16).map(item => clampNumber(item?.confidence_level, 0, 100, 0)), 0),
      families,
      matches: Math.min(data.length, 1_000)
    };
  }

  async requestForm(url, values, headers = {}) {
    return this.requestJson(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(values).toString()
    });
  }

  async requestJson(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(url, { ...options, signal: controller.signal });
      if (response?.status === 404) return { notFound: true, body: null };
      if (!response?.ok) throw new Error(`Proveedor HTTP ${Number(response?.status) || 0}`);
      const text = await response.text();
      if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw new Error('Respuesta de proveedor demasiado grande');
      return { notFound: false, body: JSON.parse(text) };
    } finally {
      clearTimeout(timeout);
    }
  }

  takeRateSlot(provider, now) {
    const windowStart = now - 60_000;
    const entries = (this.requestTimes.get(provider) ?? []).filter(value => value > windowStart);
    if (entries.length >= this.maxRequestsPerMinute) {
      this.requestTimes.set(provider, entries);
      return false;
    }
    entries.push(now);
    this.requestTimes.set(provider, entries);
    return true;
  }

  async persist() {
    const state = { schemaVersion: STORE_SCHEMA_VERSION, entries: Object.fromEntries(this.entries) };
    const temporary = `${this.statePath}.${crypto.randomUUID()}.tmp`;
    try {
      await fsp.writeFile(temporary, JSON.stringify(state, null, 2), { flag: 'wx', mode: 0o600 });
      await fsp.rename(temporary, this.statePath);
    } catch (error) {
      await fsp.rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  }

  ensureInitialized() {
    if (!this.initialized) throw new Error('Threat intelligence store is not initialized');
  }
}

function aggregateResult(sha256, sources, now, ttlMs) {
  const malicious = sources.filter(source => source.status === 'match' && source.kind === 'known-malicious');
  const context = sources.find(source => source.status === 'match' && source.kind === 'known-file-context');
  const attempted = sources.some(source => ['match', 'not-found', 'error', 'rate-limited'].includes(source.status));
  const verdict = malicious.length ? 'known-malicious' : context ? 'known-file-context' : attempted ? 'unknown' : 'unavailable';
  const confidence = malicious.length
    ? Math.max(75, ...malicious.map(source => source.confidence ?? 100))
    : context ? clampNumber(context.trust, 0, 100, 50) : 0;
  return {
    schemaVersion: STORE_SCHEMA_VERSION,
    sha256,
    verdict,
    confidence,
    queriedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    sources: sources.slice(0, MAX_SOURCES)
  };
}

function unavailableResult(sha256, reason, now) {
  return {
    schemaVersion: STORE_SCHEMA_VERSION,
    sha256,
    verdict: 'unavailable',
    confidence: 0,
    queriedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString(),
    sources: [{ provider: 'local-policy', status: reason }]
  };
}

function sanitizeState(value) {
  const entries = {};
  if (!value || typeof value !== 'object' || typeof value.entries !== 'object' || Array.isArray(value.entries)) return { entries };
  for (const [hash, input] of Object.entries(value.entries).slice(-MAX_ENTRIES)) {
    if (!SHA256.test(hash) || !input || typeof input !== 'object' || !Number.isFinite(Date.parse(input.expiresAt))) continue;
    const sources = Array.isArray(input.sources) ? input.sources.slice(0, MAX_SOURCES).map(source => ({
      provider: clampText(source?.provider, 40),
      status: clampText(source?.status, 40),
      kind: clampText(source?.kind, 60),
      confidence: clampNumber(source?.confidence, 0, 100, undefined),
      trust: clampNumber(source?.trust, 0, 100, undefined),
      signature: clampText(source?.signature, 240),
      source: clampText(source?.source, 120),
      fileName: clampText(source?.fileName, 240),
      fileSize: clampInteger(source?.fileSize, 0, Number.MAX_SAFE_INTEGER, undefined),
      firstSeen: clampText(source?.firstSeen, 40),
      families: Array.isArray(source?.families) ? source.families.slice(0, 16).map(value => clampText(value, 160)).filter(Boolean) : undefined,
      tags: Array.isArray(source?.tags) ? source.tags.slice(0, 16).map(value => clampText(value, 80)).filter(Boolean) : undefined,
      matches: clampInteger(source?.matches, 0, 1_000, undefined),
      error: clampText(source?.error, 240)
    })).filter(source => source.provider && source.status) : [];
    entries[hash.toLowerCase()] = {
      schemaVersion: STORE_SCHEMA_VERSION,
      sha256: hash.toLowerCase(),
      verdict: ['known-malicious', 'known-file-context', 'unknown', 'unavailable'].includes(input.verdict) ? input.verdict : 'unknown',
      confidence: clampNumber(input.confidence, 0, 100, 0),
      queriedAt: validDate(input.queriedAt),
      expiresAt: validDate(input.expiresAt),
      sources
    };
  }
  return { entries };
}

async function readJsonOr(file, fallback) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); }
  catch (error) {
    if (error?.code === 'ENOENT' || error?.name === 'SyntaxError') return fallback;
    throw error;
  }
}

function normalizeHash(value) {
  const hash = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!SHA256.test(hash)) {
    const error = new Error('El SHA-256 no es válido.');
    error.code = 'THREAT_INTEL_HASH_INVALID';
    throw error;
  }
  return hash;
}

function validDate(value) { return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value.slice(0, 40) : null; }
function clampText(value, maximum) { return typeof value === 'string' ? value.slice(0, maximum) : ''; }
function clampNumber(value, minimum, maximum, fallback = 0) { return Number.isFinite(Number(value)) ? Math.max(minimum, Math.min(maximum, Number(value))) : fallback; }
function clampInteger(value, minimum, maximum, fallback) { return Number.isSafeInteger(Number(value)) ? Math.max(minimum, Math.min(maximum, Number(value))) : fallback; }
