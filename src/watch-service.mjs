import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const TEMPORARY_DOWNLOAD_EXTENSIONS = new Set(['.crdownload', '.part']);

export class WatchService {
  constructor({
    engine,
    quarantine,
    emit = () => {},
    debounceMs = 650,
    maxQueue = 128,
    stabilityDelayMs = 250,
    stabilityRequired = 3,
    maxStabilityAttempts = 12,
    dedupeWindowMs = 5_000
  }) {
    this.engine = engine;
    this.quarantine = quarantine;
    this.emit = emit;
    this.debounceMs = debounceMs;
    this.maxQueue = maxQueue;
    this.stabilityDelayMs = stabilityDelayMs;
    this.stabilityRequired = stabilityRequired;
    this.maxStabilityAttempts = maxStabilityAttempts;
    this.dedupeWindowMs = dedupeWindowMs;
    this.timers = new Map();
    this.queue = [];
    this.queued = new Set();
    this.dirty = new Set();
    this.recent = new Map();
    this.drainPromise = null;
  }

  async start(target, { autoQuarantine = false } = {}) {
    await this.stop();
    const selectedRoot = path.resolve(target);
    const selectedStat = await fsp.lstat(selectedRoot);
    if (selectedStat.isSymbolicLink() || !selectedStat.isDirectory()) {
      throw new Error('The monitored target must be a regular directory');
    }
    const root = await fsp.realpath(selectedRoot);
    const stat = await fsp.lstat(root);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('The monitored target must be a regular directory');
    const controller = new AbortController();
    const session = { root, watcher: null, controller, autoQuarantine: Boolean(autoQuarantine) };
    const watcher = fs.watch(root, { recursive: true }, (_event, name) => {
      if (!name) return;
      const candidate = path.resolve(root, String(name));
      if (!isInside(root, candidate) || this.isExcluded(candidate, root)) return;
      clearTimeout(this.timers.get(candidate));
      this.timers.set(candidate, setTimeout(() => {
        this.timers.delete(candidate);
        if (this.session === session) this.enqueue(candidate);
      }, this.debounceMs));
    });
    watcher.on('error', error => { void this.handleWatcherError(session, error); });
    session.watcher = watcher;
    this.session = session;
    this.emit({ type: 'monitor-changed', payload: { active: true, path: root, autoQuarantine: Boolean(autoQuarantine) } });
    return { active: true, path: root, autoQuarantine: Boolean(autoQuarantine) };
  }

  async stop({ emit = true } = {}) {
    const previous = this.session;
    if (previous) {
      previous.controller.abort();
      previous.watcher.close();
    }
    this.session = null;
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
    this.queue.length = 0;
    this.queued.clear();
    this.dirty.clear();
    if (this.drainPromise) await this.drainPromise;
    this.recent.clear();
    if (previous && emit) this.emit({ type: 'monitor-changed', payload: { active: false } });
    return { active: false };
  }

  setAutoQuarantine(enabled) {
    if (this.session) this.session.autoQuarantine = Boolean(enabled);
  }

  async handleWatcherError(session, error) {
    if (this.session !== session) return;
    await this.stop({ emit: false });
    this.emit({ type: 'monitor-error', payload: { message: error.message } });
  }

  enqueue(file) {
    if (!this.session) return;
    if (this.queued.has(file)) {
      this.dirty.add(file);
      return;
    }
    if (this.queue.length >= this.maxQueue) {
      this.emit({ type: 'monitor-warning', payload: { message: 'Monitor queue is full; a later rescan is recommended' } });
      return;
    }
    this.queue.push(file);
    this.queued.add(file);
    if (!this.drainPromise) {
      this.drainPromise = this.drain().finally(() => { this.drainPromise = null; });
    }
  }

  async drain() {
    while (this.session && this.queue.length) {
      const file = this.queue.shift();
      try {
        await this.inspect(file, this.session);
      } finally {
        this.queued.delete(file);
        if (this.dirty.delete(file) && this.session) this.enqueue(file);
      }
    }
  }

  async inspect(file, session) {
    try {
      const stable = await waitUntilStable(file, session.controller.signal, {
        delayMs: this.stabilityDelayMs,
        required: this.stabilityRequired,
        attempts: this.maxStabilityAttempts
      });
      if (!stable) return;
      if (this.quarantine.isTransientPath(file)) return;
      const canonicalFile = await fsp.realpath(file);
      if (
        !isInside(session.root, canonicalFile)
        || this.quarantine.isTransientPath(canonicalFile)
        || this.engine.isExcludedPath(canonicalFile)
      ) return;
      const canonicalStat = await fsp.lstat(canonicalFile);
      if (
        canonicalStat.isSymbolicLink()
        || !canonicalStat.isFile()
        || fileIdentityChanged(stable.stat, canonicalStat)
      ) return;
      const previous = this.recent.get(canonicalFile);
      if (previous?.fingerprint === stable.fingerprint && Date.now() - previous.at < this.dedupeWindowMs) return;
      this.recent.set(canonicalFile, { fingerprint: stable.fingerprint, at: Date.now() });
      this.pruneRecent();
      // Real-time protection must not inherit Quick's size cutoff. The
      // exhaustive reader remains memory-bounded and checks cancellation on
      // every chunk, including for files larger than 128 MiB.
      const result = await this.engine.scanFileExhaustive(canonicalFile, {
        signal: session.controller.signal,
        expectedIdentity: snapshotIdentity(canonicalStat)
      });
      session.controller.signal.throwIfAborted();
      if (result.verdict === 'malicious' && session.autoQuarantine) {
        const metadata = await this.quarantine.isolate(canonicalFile, result, { signal: session.controller.signal });
        result.action = 'quarantined';
        result.quarantineId = metadata.id;
      }
      this.emit({ type: 'monitor-result', payload: { result } });
    } catch (error) {
      if (error.name !== 'AbortError' && error.code !== 'ENOENT') {
        this.emit({ type: 'monitor-error', payload: { path: file, message: error.message } });
      }
    }
  }

  isExcluded(candidate, root) {
    if (isTemporaryDownload(candidate)) return true;
    if (this.quarantine.isTransientPath(candidate)) return true;
    return this.engine.isExcludedPath(candidate);
  }

  pruneRecent() {
    const oldestAllowed = Date.now() - this.dedupeWindowMs;
    for (const [file, entry] of this.recent) if (entry.at < oldestAllowed) this.recent.delete(file);
    while (this.recent.size > 512) this.recent.delete(this.recent.keys().next().value);
  }
}

async function waitUntilStable(file, signal, { delayMs, required, attempts }) {
  let previous;
  let stableCount = 0;
  for (let attempt = 0; attempt < attempts; attempt++) {
    signal.throwIfAborted();
    let stat;
    try { stat = await fsp.lstat(file); }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
    if (!stat.isFile() || stat.isSymbolicLink()) return false;
    const current = `${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`;
    stableCount = previous === current ? stableCount + 1 : 1;
    if (stableCount >= required) return { stat, fingerprint: current };
    previous = current;
    await delay(delayMs, undefined, { signal });
  }
  return false;
}

export function isTemporaryDownload(file) {
  return TEMPORARY_DOWNLOAD_EXTENSIONS.has(path.extname(String(file ?? '')).toLowerCase());
}

function snapshotIdentity(stat) {
  return { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs };
}

function fileIdentityChanged(before, after) {
  if (before.dev && after.dev && before.dev !== after.dev) return true;
  if (before.ino && after.ino && before.ino !== after.ino) return true;
  return before.size !== after.size || before.mtimeMs !== after.mtimeMs;
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}
