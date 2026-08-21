import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { validateDefinitions, verifySignedDefinitionEnvelope } from './definition-security.mjs';

const MAX_ENVELOPE_BYTES = 16 * 1024 * 1024;
const MAX_BACKUPS = 4;
const STATE_SCHEMA_VERSION = 1;
const ACTIVE_FILE = 'active.bundle.json';
const STATE_FILE = 'state.json';
const BUNDLED_DEFINITIONS = path.join('definitions', 'signatures.json');

/**
 * Stores signed detection definitions outside the packaged application.
 *
 * The store deliberately has no network code. A trusted release channel can
 * feed it an envelope later, while tests and administrators can exercise the
 * exact same verification and rollback path with a local file.
 */
export class DefinitionUpdateStore {
  constructor({
    baseDirectory,
    dataDirectory,
    publicKeys = {},
    minimumVersion = 0,
    maxBackups = MAX_BACKUPS,
    clock = () => new Date()
  }) {
    this.baseDirectory = path.resolve(baseDirectory);
    this.dataDirectory = path.resolve(dataDirectory);
    this.publicKeys = normalizePublicKeys(publicKeys);
    this.minimumVersion = Number.isSafeInteger(minimumVersion) && minimumVersion >= 0 ? minimumVersion : 0;
    this.maxBackups = Math.max(1, Math.min(MAX_BACKUPS, Number(maxBackups) || MAX_BACKUPS));
    this.clock = clock;
    this.directory = path.join(this.dataDirectory, 'definition-updates');
    this.backupDirectory = path.join(this.directory, 'backups');
    this.activePath = path.join(this.directory, ACTIVE_FILE);
    this.statePath = path.join(this.directory, STATE_FILE);
    this.initialized = false;
    this.bundledDefinitions = null;
    this.currentDefinitions = null;
    this.currentSource = 'bundled';
    this.currentEnvelope = null;
    this.state = emptyState();
  }

  async init() {
    await fsp.mkdir(this.backupDirectory, { recursive: true });
    this.bundledDefinitions = validateDefinitions(await readJson(path.join(this.baseDirectory, BUNDLED_DEFINITIONS)));
    this.state = sanitizeState(await readJsonOr(this.statePath, {}));
    this.currentDefinitions = this.bundledDefinitions;
    this.currentSource = 'bundled';
    this.currentEnvelope = null;

    try {
      const envelope = await readEnvelope(this.activePath);
      const definitions = verifySignedDefinitionEnvelope(envelope, {
        publicKeys: this.publicKeys,
        minimumVersion: Math.max(this.minimumVersion, this.bundledDefinitions.version, this.state.currentVersion)
      });
      this.currentDefinitions = definitions;
      this.currentSource = 'updated';
      this.currentEnvelope = envelope;
      this.state.currentVersion = definitions.version;
      this.state.lastError = null;
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        this.state.lastError = clampError(error);
        this.currentDefinitions = this.bundledDefinitions;
        this.currentSource = 'bundled';
        this.currentEnvelope = null;
      }
    }

    this.initialized = true;
    return this.status();
  }

  status() {
    const currentVersion = this.currentDefinitions?.version ?? this.bundledDefinitions?.version ?? 0;
    return {
      schemaVersion: STATE_SCHEMA_VERSION,
      currentVersion,
      bundledVersion: this.bundledDefinitions?.version ?? 0,
      source: this.currentSource,
      signature: this.currentSource === 'updated' ? {
        status: 'verified',
        keyId: safeKeyId(this.currentEnvelope?.keyId)
      } : { status: 'bundled', keyId: null },
      rollbackAvailable: this.currentSource === 'updated' && (this.state.backups.length > 0 || currentVersion > (this.bundledDefinitions?.version ?? 0)),
      lastAppliedAt: this.state.lastAppliedAt,
      lastRollbackAt: this.state.lastRollbackAt,
      lastError: this.state.lastError,
      updateChannelConfigured: Object.keys(this.publicKeys).length > 0,
      networkEnabled: false
    };
  }

  async applyEnvelope(envelope) {
    this.ensureInitialized();
    const serialized = serializeEnvelope(envelope);
    if (Buffer.byteLength(serialized, 'utf8') > MAX_ENVELOPE_BYTES) throw definitionError('DEFINITIONS_TOO_LARGE', 'El paquete de definiciones supera el límite permitido.');
    if (!Object.keys(this.publicKeys).length) throw definitionError('DEFINITIONS_TRUST_NOT_CONFIGURED', 'No hay ninguna clave pública de definiciones configurada.');

    const definitions = verifySignedDefinitionEnvelope(envelope, {
      publicKeys: this.publicKeys,
      minimumVersion: Math.max(this.minimumVersion, this.bundledDefinitions.version, this.currentDefinitions.version + 1)
    });
    const previous = {
      definitions: this.currentDefinitions,
      source: this.currentSource,
      envelope: this.currentEnvelope,
      state: structuredClone(this.state)
    };
    const backup = this.currentSource === 'updated' ? await this.createBackup() : null;
    const nextState = {
      ...this.state,
      currentVersion: definitions.version,
      lastAppliedAt: this.clock().toISOString(),
      lastRollbackAt: this.state.lastRollbackAt,
      lastError: null,
      backups: backup ? [...this.state.backups, backup].slice(-this.maxBackups) : this.state.backups.slice(-this.maxBackups)
    };

    try {
      await writeAtomic(this.activePath, serialized);
      const persisted = await readEnvelope(this.activePath);
      verifySignedDefinitionEnvelope(persisted, {
        publicKeys: this.publicKeys,
        minimumVersion: Math.max(this.minimumVersion, this.bundledDefinitions.version, this.currentDefinitions.version + 1)
      });
      await writeAtomic(this.statePath, JSON.stringify(nextState, null, 2));
      this.state = sanitizeState(nextState);
      this.currentDefinitions = definitions;
      this.currentSource = 'updated';
      this.currentEnvelope = persisted;
      return { ...this.status(), applied: true };
    } catch (error) {
      await this.restorePrevious(previous).catch(() => {});
      throw error;
    }
  }

  async rollback() {
    this.ensureInitialized();
    if (this.currentSource !== 'updated') throw definitionError('DEFINITIONS_ROLLBACK_UNAVAILABLE', 'No hay una actualización de definiciones que revertir.');
    const previous = {
      definitions: this.currentDefinitions,
      source: this.currentSource,
      envelope: this.currentEnvelope,
      state: structuredClone(this.state)
    };
    const candidate = this.state.backups.length ? this.state.backups[this.state.backups.length - 1] : null;
    try {
      if (candidate) {
        const envelope = await readEnvelope(path.join(this.backupDirectory, candidate.file));
        const definitions = verifySignedDefinitionEnvelope(envelope, {
          publicKeys: this.publicKeys,
          minimumVersion: Math.max(this.minimumVersion, this.bundledDefinitions.version)
        });
        if (definitions.version >= this.currentDefinitions.version) throw definitionError('DEFINITIONS_ROLLBACK_INVALID', 'La copia anterior no es una versión inferior.');
        await writeAtomic(this.activePath, serializeEnvelope(envelope));
        const nextState = {
          ...this.state,
          currentVersion: definitions.version,
          lastRollbackAt: this.clock().toISOString(),
          lastError: null,
          backups: this.state.backups.slice(0, -1)
        };
        await writeAtomic(this.statePath, JSON.stringify(nextState, null, 2));
        this.state = sanitizeState(nextState);
        this.currentDefinitions = definitions;
        this.currentSource = 'updated';
        this.currentEnvelope = envelope;
        await fsp.rm(path.join(this.backupDirectory, candidate.file), { force: true });
        return { ...this.status(), rolledBack: true };
      }

      if (this.currentDefinitions.version <= this.bundledDefinitions.version) throw definitionError('DEFINITIONS_ROLLBACK_UNAVAILABLE', 'No hay una copia anterior disponible.');
      await fsp.rm(this.activePath, { force: true });
      const nextState = {
        ...this.state,
        currentVersion: this.bundledDefinitions.version,
        lastRollbackAt: this.clock().toISOString(),
        lastError: null,
        backups: []
      };
      await writeAtomic(this.statePath, JSON.stringify(nextState, null, 2));
      this.state = sanitizeState(nextState);
      this.currentDefinitions = this.bundledDefinitions;
      this.currentSource = 'bundled';
      this.currentEnvelope = null;
      return { ...this.status(), rolledBack: true };
    } catch (error) {
      await this.restorePrevious(previous).catch(() => {});
      throw error;
    }
  }

  ensureInitialized() {
    if (!this.initialized || !this.currentDefinitions || !this.bundledDefinitions) throw new Error('Definition update store is not initialized');
  }

  async createBackup() {
    const version = this.currentDefinitions.version;
    const file = `definition-${version}-${Date.now()}-${crypto.randomUUID()}.bundle.json`;
    await fsp.copyFile(this.activePath, path.join(this.backupDirectory, file));
    return { file, version, createdAt: this.clock().toISOString() };
  }

  async restorePrevious(previous) {
    this.state = previous.state;
    this.currentDefinitions = previous.definitions;
    this.currentSource = previous.source;
    this.currentEnvelope = previous.envelope;
    if (previous.source === 'updated' && previous.envelope) await writeAtomic(this.activePath, serializeEnvelope(previous.envelope));
    else await fsp.rm(this.activePath, { force: true });
    await writeAtomic(this.statePath, JSON.stringify(this.state, null, 2));
  }
}

export function serializeEnvelope(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw definitionError('DEFINITIONS_ENVELOPE_INVALID', 'El paquete de definiciones no es válido.');
  const output = {
    schemaVersion: 1,
    keyId: safeKeyId(value.keyId),
    payloadBase64: value.payloadBase64,
    signatureBase64: value.signatureBase64
  };
  if (!output.keyId || !isCanonicalBase64(output.payloadBase64) || !isCanonicalBase64(output.signatureBase64)) {
    throw definitionError('DEFINITIONS_ENVELOPE_INVALID', 'El paquete de definiciones no es válido.');
  }
  return JSON.stringify(output);
}

function emptyState() {
  return { schemaVersion: STATE_SCHEMA_VERSION, currentVersion: 0, lastAppliedAt: null, lastRollbackAt: null, lastError: null, backups: [] };
}

function sanitizeState(value) {
  const input = value && typeof value === 'object' ? value : {};
  const backups = Array.isArray(input.backups) ? input.backups.slice(-MAX_BACKUPS).map(item => {
    const file = typeof item?.file === 'string' && path.basename(item.file) === item.file && item.file.endsWith('.bundle.json') ? item.file : null;
    const version = Number.isSafeInteger(item?.version) && item.version >= 1 ? item.version : 0;
    if (!file || !version) return null;
    return { file, version, createdAt: validDate(item.createdAt) };
  }).filter(Boolean) : [];
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    currentVersion: Number.isSafeInteger(input.currentVersion) && input.currentVersion >= 0 ? input.currentVersion : 0,
    lastAppliedAt: validDate(input.lastAppliedAt),
    lastRollbackAt: validDate(input.lastRollbackAt),
    lastError: typeof input.lastError === 'string' ? input.lastError.slice(0, 500) : null,
    backups
  };
}

async function readEnvelope(file) {
  const stat = await fsp.stat(file);
  if (!stat.isFile() || stat.size > MAX_ENVELOPE_BYTES) throw definitionError('DEFINITIONS_ENVELOPE_INVALID', 'El paquete de definiciones no es válido.');
  const value = JSON.parse(await fsp.readFile(file, 'utf8'));
  serializeEnvelope(value);
  return value;
}

async function readJson(file) { return JSON.parse(await fsp.readFile(file, 'utf8')); }

async function readJsonOr(file, fallback) {
  try { return await readJson(file); }
  catch (error) {
    if (error?.code === 'ENOENT' || error?.name === 'SyntaxError') return fallback;
    throw error;
  }
}

async function writeAtomic(file, contents) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {
    await fsp.writeFile(temporary, contents, { flag: 'wx', mode: 0o600 });
    await fsp.rename(temporary, file);
  } catch (error) {
    await fsp.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

function normalizePublicKeys(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value).slice(0, 8).filter(([key, pem]) => safeKeyId(key) && typeof pem === 'string' && pem.length <= 8_192).map(([key, pem]) => [key, pem]));
}

function safeKeyId(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  return /^[A-Za-z0-9._-]{1,80}$/.test(text) ? text : null;
}

function isCanonicalBase64(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  try { return Buffer.from(value, 'base64').toString('base64') === value; }
  catch { return false; }
}

function validDate(value) { return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value.slice(0, 40) : null; }

function clampError(error) { return String(error?.message ?? 'No se pudieron validar las definiciones.').slice(0, 500); }

function definitionError(code, message) { const error = new Error(message); error.code = code; return error; }
