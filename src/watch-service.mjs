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
    dedupeWindowMs = 5_000,
    maxPendingEvents = Math.max(128, maxQueue * 4),
    warningIntervalMs = 30_000
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
    this.maxPendingEvents = Math.max(maxQueue, maxPendingEvents);
    this.warningIntervalMs = warningIntervalMs;
    this.pendingCandidates = new Map();
    this.pendingTimer = null;
    this.queue = [];
    this.queued = new Set();
    this.dirty = new Set();
    this.recent = new Map();
    this.drainPromise = null;
    this.lastWarningAt = 0;
    this.metrics = {
      eventsReceived: 0,
      eventsCoalesced: 0,
      eventsDropped: 0,
      filesInspected: 0,
      peakPendingEvents: 0,
      peakQueueDepth: 0
    };
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
      this.schedule(candidate, session);
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
    if (this.pendingTimer) clearTimeout(this.pendingTimer);
    this.pendingTimer = null;
    this.pendingCandidates.clear();
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

  schedule(file, session = this.session, now = Date.now()) {
    if (!session || this.session !== session) return false;
    this.metrics.eventsReceived++;
    if (this.pendingCandidates.has(file)) {
      this.metrics.eventsCoalesced++;
    } else if (this.pendingCandidates.size >= this.maxPendingEvents) {
      this.metrics.eventsDropped++;
      this.emitCapacityWarning(now);
      return false;
    }
    this.pendingCandidates.set(file, { deadline: now + this.debounceMs, session });
    this.metrics.peakPendingEvents = Math.max(this.metrics.peakPendingEvents, this.pendingCandidates.size);
    this.armPendingTimer();
    return true;
  }

  armPendingTimer() {
    if (this.pendingTimer || !this.pendingCandidates.size) return;
    let earliest = Number.POSITIVE_INFINITY;
    for (const pending of this.pendingCandidates.values()) earliest = Math.min(earliest, pending.deadline);
    this.pendingTimer = setTimeout(() => this.flushPendingCandidates(), Math.max(0, earliest - Date.now()));
    this.pendingTimer.unref?.();
  }

  flushPendingCandidates(now = Date.now()) {
    this.pendingTimer = null;
    for (const [file, pending] of this.pendingCandidates) {
      if (pending.deadline > now) continue;
      this.pendingCandidates.delete(file);
      if (this.session === pending.session) this.enqueue(file);
    }
    this.armPendingTimer();
  }

  enqueue(file) {
    if (!this.session) return;
    if (this.queued.has(file)) {
      this.dirty.add(file);
      return;
    }
    if (this.queue.length >= this.maxQueue) {
      this.metrics.eventsDropped++;
      this.emitCapacityWarning();
      return;
    }
    this.queue.push(file);
    this.queued.add(file);
    this.metrics.peakQueueDepth = Math.max(this.metrics.peakQueueDepth, this.queue.length);
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
      this.metrics.filesInspected++;
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

  emitCapacityWarning(now = Date.now()) {
    if (this.lastWarningAt && now - this.lastWarningAt < this.warningIntervalMs) return;
    this.lastWarningAt = now;
    this.emit({ type: 'monitor-warning', payload: { message: 'Monitor capacity was reached; a later rescan is recommended' } });
  }

  status() {
    return {
      active: Boolean(this.session),
      pendingEvents: this.pendingCandidates.size,
      queueDepth: this.queue.length,
      queueLimit: this.maxQueue,
      pendingLimit: this.maxPendingEvents,
      ...this.metrics
    };
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
