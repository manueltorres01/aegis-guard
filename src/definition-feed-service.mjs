import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';

const STATE_SCHEMA_VERSION = 1;
const MAX_FEED_BYTES = 16 * 1024 * 1024;
const DEFAULT_INTERVAL_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_MAX_BACKOFF_MS = 72 * 60 * 60 * 1_000;

/**
 * Daily, conditional fetch for a signed Aegis definition envelope.
 *
 * This service deliberately downloads only the compact, maintainer-signed
 * envelope. It never talks to MalwareBazaar/ThreatFox directly from a client,
 * never accepts raw definition JSON and never bypasses DefinitionUpdateStore's
 * Ed25519 verification and rollback checks.
 */
export class DefinitionFeedService {
  constructor({
    dataDirectory,
    config = {},
    fetchImpl = globalThis.fetch,
    clock = () => new Date(),
    applyEnvelope = async () => { throw new Error('No definition envelope applier configured'); },
    isBusy = () => false
  } = {}) {
    if (!dataDirectory) throw new TypeError('Definition feed data directory is required');
    this.directory = path.join(path.resolve(dataDirectory), 'definition-updates');
    this.statePath = path.join(this.directory, 'feed-state.json');
    this.config = normalizeConfig(config);
    this.fetchImpl = typeof fetchImpl === 'function' ? fetchImpl : null;
    this.clock = clock;
    this.applyEnvelope = applyEnvelope;
    this.isBusy = isBusy;
    this.state = emptyState();
    this.initialized = false;
    this.inFlight = null;
  }

  async init() {
    await fsp.mkdir(this.directory, { recursive: true });
    this.state = sanitizeState(await readJsonOr(this.statePath, {}));
    this.initialized = true;
    return this.status();
  }

  status(now = this.clock()) {
    const configured = this.config.enabled && Boolean(this.config.url) && Boolean(this.fetchImpl);
    const nextCheckAt = this.state.nextCheckAt;
    const due = configured && (!nextCheckAt || Date.parse(nextCheckAt) <= now.getTime());
    return {
      schemaVersion: STATE_SCHEMA_VERSION,
      enabled: this.config.enabled,
      configured,
      url: this.config.url,
      intervalHours: this.config.intervalMs / 3_600_000,
      due,
      inFlight: Boolean(this.inFlight),
      lastCheckedAt: this.state.lastCheckedAt,
      lastSuccessfulAt: this.state.lastSuccessfulAt,
      nextCheckAt,
      lastAppliedVersion: this.state.lastAppliedVersion,
      lastError: this.state.lastError,
      consecutiveFailures: this.state.consecutiveFailures,
      etagStored: Boolean(this.state.etag),
      lastModifiedStored: Boolean(this.state.lastModified)
    };
  }

  async check({ force = false } = {}) {
    this.ensureInitialized();
    const now = this.clock();
    if (!this.config.enabled || !this.config.url) return { ...this.status(now), result: 'not-configured' };
    if (!this.fetchImpl) return this.recordFailure(now, 'No hay transporte HTTP disponible.', 'unavailable');
    if (this.inFlight) return { ...this.status(now), result: 'busy' };
    if (!force && this.state.nextCheckAt && Date.parse(this.state.nextCheckAt) > now.getTime()) {
      return { ...this.status(now), result: 'not-due' };
    }
    this.inFlight = this.performCheck(now).finally(() => { this.inFlight = null; });
    return this.inFlight;
  }

  async performCheck(now) {
    if (this.isBusy()) return { ...this.status(now), result: 'busy' };
    const headers = {
      Accept: 'application/json',
      'Cache-Control': 'no-cache',
      'User-Agent': 'Aegis-Guard-definition-updater/1'
    };
    if (this.state.etag) headers['If-None-Match'] = this.state.etag;
    if (this.state.lastModified) headers['If-Modified-Since'] = this.state.lastModified;

    try {
      const response = await this.request(headers);
      if (response.status === 304) {
        this.state = successState(this.state, now, this.state.lastAppliedVersion, this.config.intervalMs);
        await this.persist();
        return { ...this.status(now), result: 'not-modified' };
      }
      const envelope = response.body;
      let applied = false;
      let update = null;
      try {
        update = await this.applyEnvelope(envelope);
        applied = true;
      } catch (error) {
        if (error?.code !== 'DEFINITIONS_ROLLBACK' && !/rollback/i.test(String(error?.message ?? ''))) throw error;
      }
      this.state = successState({
        ...this.state,
        etag: headerValue(response.headers, 'etag'),
        lastModified: headerValue(response.headers, 'last-modified')
      }, now, update?.currentVersion ?? this.state.lastAppliedVersion, this.config.intervalMs);
      await this.persist();
      return { ...this.status(now), result: applied ? 'applied' : 'already-current', version: update?.currentVersion ?? this.state.lastAppliedVersion };
    } catch (error) {
      return this.recordFailure(now, clampText(error?.message, 500) || 'No se pudo consultar el canal de definiciones.', 'error');
    }
  }

  async request(headers) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const response = await this.fetchImpl(this.config.url, { method: 'GET', headers, redirect: 'follow', signal: controller.signal });
      if (response.status === 304) return { status: 304, headers: response.headers ?? new Headers(), body: null };
      if (!response.ok) throw new Error(`Canal de definiciones HTTP ${Number(response.status) || 0}`);
      const text = await response.text();
      if (Buffer.byteLength(text, 'utf8') > MAX_FEED_BYTES) throw new Error('El paquete remoto de definiciones supera el límite permitido.');
      let body;
      try { body = JSON.parse(text); }
      catch { throw new Error('El canal de definiciones no devolvió JSON válido.'); }
      return { status: response.status, headers: response.headers ?? new Headers(), body };
    } finally {
      clearTimeout(timeout);
    }
  }

  async recordFailure(now, message, result = 'error') {
    this.state = failureState(this.state, now, message, this.config.intervalMs, this.config.maxBackoffMs);
    await this.persist();
    return { ...this.status(now), result };
  }

  async persist() {
    const temporary = `${this.statePath}.${crypto.randomUUID()}.tmp`;
    try {
      await fsp.writeFile(temporary, JSON.stringify(this.state, null, 2), { flag: 'wx', mode: 0o600 });
      await fsp.rename(temporary, this.statePath);
    } catch (error) {
      await fsp.rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  }

  ensureInitialized() {
    if (!this.initialized) throw new Error('Definition feed service is not initialized');
  }
}

function normalizeConfig(value) {
  const input = value && typeof value === 'object' ? value : {};
  const url = safeHttpsUrl(input.url);
  return {
    enabled: input.enabled === true,
    url,
    intervalMs: clampInteger(Number(input.intervalHours) * 3_600_000, 24 * 3_600_000, 7 * 24 * 3_600_000, DEFAULT_INTERVAL_MS),
    timeoutMs: clampInteger(input.timeoutMs, 2_000, 30_000, 8_000),
    maxBackoffMs: clampInteger(Number(input.maxBackoffHours) * 3_600_000, 24 * 3_600_000, 7 * 24 * 3_600_000, DEFAULT_MAX_BACKOFF_MS)
  };
}

function safeHttpsUrl(value) {
  if (typeof value !== 'string' || value.length > 2_000) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.port) return null;
    if (['localhost', '127.0.0.1', '::1'].includes(url.hostname.toLowerCase())) return null;
    return url.toString();
  } catch { return null; }
}

function emptyState() {
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    etag: null,
    lastModified: null,
    lastCheckedAt: null,
    lastSuccessfulAt: null,
    nextCheckAt: null,
    lastAppliedVersion: 0,
    lastError: null,
    consecutiveFailures: 0
  };
}

function sanitizeState(value) {
  const input = value && typeof value === 'object' ? value : {};
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    etag: clampHeader(input.etag),
    lastModified: clampHeader(input.lastModified),
    lastCheckedAt: validDate(input.lastCheckedAt),
    lastSuccessfulAt: validDate(input.lastSuccessfulAt),
    nextCheckAt: validDate(input.nextCheckAt),
    lastAppliedVersion: Number.isSafeInteger(input.lastAppliedVersion) && input.lastAppliedVersion >= 0 ? input.lastAppliedVersion : 0,
    lastError: clampText(input.lastError, 500) || null,
    consecutiveFailures: Number.isSafeInteger(input.consecutiveFailures) && input.consecutiveFailures >= 0 ? Math.min(input.consecutiveFailures, 16) : 0
  };
}

function successState(previous, now, version, intervalMs = DEFAULT_INTERVAL_MS) {
  return {
    ...sanitizeState(previous),
    lastCheckedAt: now.toISOString(),
    lastSuccessfulAt: now.toISOString(),
    nextCheckAt: new Date(now.getTime() + intervalMs).toISOString(),
    lastAppliedVersion: Number.isSafeInteger(version) ? version : previous.lastAppliedVersion ?? 0,
    lastError: null,
    consecutiveFailures: 0
  };
}

function failureState(previous, now, message, intervalMs, maxBackoffMs) {
  const failures = Math.min(16, (previous.consecutiveFailures ?? 0) + 1);
  const backoff = Math.min(maxBackoffMs, intervalMs * (2 ** Math.min(6, failures - 1)));
  return {
    ...sanitizeState(previous),
    lastCheckedAt: now.toISOString(),
    nextCheckAt: new Date(now.getTime() + backoff).toISOString(),
    lastError: clampText(message, 500),
    consecutiveFailures: failures
  };
}

function headerValue(headers, name) {
  try {
    const value = headers?.get?.(name);
    return clampHeader(value);
  } catch { return null; }
}

function clampHeader(value) { return typeof value === 'string' && value.length <= 500 ? value : null; }
function clampText(value, maximum) { return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maximum) : ''; }
function validDate(value) { return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value.slice(0, 40) : null; }
function clampInteger(value, minimum, maximum, fallback) { return Number.isSafeInteger(Number(value)) ? Math.max(minimum, Math.min(maximum, Number(value))) : fallback; }

async function readJsonOr(file, fallback) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); }
  catch (error) {
    if (error?.code === 'ENOENT' || error?.name === 'SyntaxError') return fallback;
    throw error;
  }
}
