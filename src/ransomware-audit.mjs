import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const CANARY_PREFIX = '_AegisGuard_Canary_';
const CANARY_TEXT = 'Aegis Guard ransomware audit canary. This document contains no personal data and is safe to delete after disabling ransomware audit.\r\n';

export class RansomwareAudit {
  constructor({
    roots = [],
    emit = () => {},
    watcherFactory = fs.watch,
    clock = () => Date.now(),
    windowMs = 10_000,
    changeThreshold = 40,
    deleteThreshold = 12,
    extensionThreshold = 8,
    alertCooldownMs = 60_000
  } = {}) {
    this.roots = normalizeRoots(roots);
    this.emit = emit;
    this.watcherFactory = watcherFactory;
    this.clock = clock;
    this.windowMs = boundedInteger(windowMs, 1_000, 60_000, 'windowMs');
    this.changeThreshold = boundedInteger(changeThreshold, 5, 10_000, 'changeThreshold');
    this.deleteThreshold = boundedInteger(deleteThreshold, 3, 10_000, 'deleteThreshold');
    this.extensionThreshold = boundedInteger(extensionThreshold, 3, 10_000, 'extensionThreshold');
    this.alertCooldownMs = boundedInteger(alertCooldownMs, 1_000, 3_600_000, 'alertCooldownMs');
    this.sessions = [];
    this.canaries = new Map();
    this.records = [];
    this.alerts = [];
    this.lastSeen = new Map();
    this.recentDeletes = new Map();
    this.lastAlert = new Map();
    this.active = false;
    this.degradedRoots = [];
  }

  async start() {
    if (this.active) return this.status();
    this.degradedRoots = [];
    for (const root of this.roots) {
      try {
        const stat = await fsp.lstat(root);
        if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Protected root is not a regular directory');
        const canary = await ensureCanary(root);
        this.canaries.set(pathKey(root), canary);
        const watcher = this.watcherFactory(root, { recursive: process.platform === 'win32', persistent: true }, (eventType, fileName) => {
          void this.inspectEvent(root, canary, eventType, fileName).catch(() => {
            this.markDegraded(root, 'event-inspection-failed');
          });
        });
        watcher.on?.('error', () => this.markDegraded(root, 'watcher-failed'));
        this.sessions.push({ root, canary, watcher });
      } catch {
        this.markDegraded(root, 'startup-failed');
      }
    }
    this.active = this.sessions.length > 0;
    return this.status();
  }

  async stop({ removeCanaries = false } = {}) {
    const sessions = this.sessions.splice(0);
    this.active = false;
    for (const session of sessions) {
      try { session.watcher.close(); } catch { /* already closed */ }
    }
    if (removeCanaries) {
      await Promise.allSettled([...this.canaries.values()].map(removeOwnedCanary));
      this.canaries.clear();
    }
    this.records = [];
    this.lastSeen.clear();
    this.recentDeletes.clear();
    return this.status();
  }

  status() {
    return {
      mode: 'audit',
      enabled: this.active,
      rootsConfigured: this.roots.length,
      rootsObserved: this.sessions.length,
      degradedRoots: this.degradedRoots.length,
      canariesActive: this.sessions.filter(session => session.canary?.owned).length,
      processAttribution: 'unavailable',
      blocking: false,
      recentAlerts: this.alerts.slice(0, 20)
    };
  }

  async inspectEvent(root, canary, eventType, fileName) {
    if (!this.active || !['change', 'rename'].includes(eventType) || (!Buffer.isBuffer(fileName) && typeof fileName !== 'string')) return;
    const relative = String(fileName).replace(/\0/g, '');
    if (!relative || path.isAbsolute(relative)) return;
    const candidate = path.resolve(root, relative);
    if (!isWithin(root, candidate)) return;
    const now = this.clock();
    const dedupeKey = `${eventType}:${pathKey(candidate)}`;
    if (now - (this.lastSeen.get(dedupeKey) ?? 0) < 100) return;
    this.lastSeen.set(dedupeKey, now);

    if (canary?.owned && pathKey(candidate) === pathKey(canary.path)) {
      const intact = await canaryIsIntact(canary);
      if (!intact) this.raise(root, 'canary-tamper', 'critical', { changed: 1, deleted: 0, extensionChanges: 0 }, path.basename(candidate));
      return;
    }

    let exists = true;
    let regularFile = false;
    try {
      const stat = await fsp.lstat(candidate);
      regularFile = stat.isFile() && !stat.isSymbolicLink();
    } catch (error) {
      if (error.code !== 'ENOENT') return;
      exists = false;
    }
    if (exists && !regularFile) return;

    let kind = eventType === 'change' ? 'changed' : exists ? 'created-or-renamed' : 'deleted-or-renamed';
    let extensionChanged = false;
    if (!exists) {
      this.recentDeletes.set(pathKey(candidate), now);
    } else if (eventType === 'rename') {
      const directory = pathKey(path.dirname(candidate));
      const newName = path.basename(candidate).toLowerCase();
      for (const [deletedPath, deletedAt] of this.recentDeletes) {
        if (now - deletedAt > this.windowMs) { this.recentDeletes.delete(deletedPath); continue; }
        if (pathKey(path.dirname(deletedPath)) !== directory) continue;
        const deletedName = path.basename(deletedPath).toLowerCase();
        if (newName.startsWith(`${deletedName}.`)) { extensionChanged = true; kind = 'extension-changed'; break; }
      }
    }

    this.records.push({ at: now, path: pathKey(candidate), kind, deleted: !exists, extensionChanged });
    this.prune(now);
    const distinct = new Set(this.records.map(record => record.path)).size;
    const deleted = new Set(this.records.filter(record => record.deleted).map(record => record.path)).size;
    const extensionChanges = new Set(this.records.filter(record => record.extensionChanged).map(record => record.path)).size;
    const counts = { changed: distinct, deleted, extensionChanges };
    if (extensionChanges >= this.extensionThreshold) this.raise(root, 'mass-extension-change', 'high', counts, path.basename(candidate));
    else if (deleted >= this.deleteThreshold) this.raise(root, 'high-rate-deletion', 'high', counts, path.basename(candidate));
    else if (distinct >= this.changeThreshold) this.raise(root, 'high-rate-file-change', 'medium', counts, path.basename(candidate));
  }

  prune(now) {
    this.records = this.records.filter(record => now - record.at <= this.windowMs).slice(-20_000);
    for (const [key, at] of this.lastSeen) if (now - at > this.windowMs) this.lastSeen.delete(key);
    for (const [key, at] of this.recentDeletes) if (now - at > this.windowMs) this.recentDeletes.delete(key);
  }

  raise(root, kind, severity, counts, fileName) {
    const now = this.clock();
    const key = `${pathKey(root)}:${kind}`;
    if (now - (this.lastAlert.get(key) ?? 0) < this.alertCooldownMs) return;
    this.lastAlert.set(key, now);
    const alert = {
      id: crypto.randomUUID(),
      at: new Date(now).toISOString(),
      kind,
      severity,
      mode: 'audit',
      rootLabel: path.basename(root) || path.parse(root).root,
      fileName: String(fileName ?? '').slice(0, 260),
      counts,
      process: { attributed: false, reason: 'Native process-write telemetry is not available in this build' },
      action: 'observed-only',
      explanation: explanationFor(kind)
    };
    this.alerts = [alert, ...this.alerts].slice(0, 100);
    this.emit({ type: 'ransomware-audit-alert', payload: alert });
  }

  markDegraded(root, reason) {
    const key = pathKey(root);
    if (!this.degradedRoots.some(item => pathKey(item.root) === key)) this.degradedRoots.push({ root, reason });
  }
}

async function ensureCanary(root) {
  const suffix = crypto.createHash('sha256').update(pathKey(root)).digest('hex').slice(0, 12);
  const file = path.join(root, `${CANARY_PREFIX}${suffix}.txt`);
  try {
    await fsp.writeFile(file, CANARY_TEXT, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const current = await fsp.readFile(file, 'utf8').catch(() => null);
    if (current !== CANARY_TEXT) return { path: file, owned: false, sha256: null };
  }
  return { path: file, owned: true, sha256: hash(CANARY_TEXT) };
}

async function canaryIsIntact(canary) {
  try { return hash(await fsp.readFile(canary.path)) === canary.sha256; }
  catch { return false; }
}

async function removeOwnedCanary(canary) {
  if (!canary?.owned || !await canaryIsIntact(canary)) return false;
  await fsp.rm(canary.path);
  return true;
}

function explanationFor(kind) {
  return ({
    'canary-tamper': 'A ransomware audit canary was modified or removed.',
    'mass-extension-change': 'Multiple files appear to have received an additional extension in a short window.',
    'high-rate-deletion': 'Many distinct files disappeared during the audit window.',
    'high-rate-file-change': 'Many distinct files changed during the audit window.'
  })[kind] ?? 'Unusual file activity was observed.';
}

function normalizeRoots(roots) {
  if (!Array.isArray(roots)) throw new TypeError('roots must be an array');
  const output = [];
  const seen = new Set();
  for (const value of roots.slice(0, 8)) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) continue;
    const resolved = path.resolve(value);
    const key = pathKey(resolved);
    if (!seen.has(key)) { seen.add(key); output.push(resolved); }
  }
  return output;
}

function isWithin(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function pathKey(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function boundedInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`Invalid ${label}`);
  return value;
}

function hash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
