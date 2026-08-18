import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { ScanEngine } from './engine.mjs';
import { Quarantine } from './quarantine.mjs';
import { createHarmlessSimulation } from './simulator.mjs';
import { WatchService } from './watch-service.mjs';
import { discoverWindowsDriveRoots } from './drive-roots.mjs';
import { createAuthenticodeVerifier } from './authenticode.mjs';
import { loadJson, pathExists } from './util.mjs';

const DEFAULT_SETTINGS = Object.freeze({
  theme: 'system',
  autoQuarantine: false,
  notifications: true,
  checkUpdates: true,
  updateChannel: 'stable',
  launchAtStartup: true
});

const MAX_RETAINED_RESULTS = 5_000;
const MAX_RETAINED_RESULT_BYTES = 8 * 1024 * 1024;
const MAX_STORED_JOBS = 4;
const MAX_TRAVERSAL_EVENTS = 250;
const RESULT_PRIORITY = Object.freeze({ skipped: 1, error: 2, suspicious: 3, malicious: 4 });

export class AppService {
  constructor({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    quarantineKeyBase64,
    driveRootsProvider = discoverWindowsDriveRoots,
    watchOptions = {},
    emit = () => {}
  }) {
    this.baseDirectory = path.resolve(baseDirectory);
    this.dataDirectory = path.resolve(dataDirectory);
    this.downloadsDirectory = path.resolve(downloadsDirectory);
    this.emit = emit;
    this.driveRootsProvider = driveRootsProvider;
    this.watchOptions = watchOptions;
    this.quarantineKey = decodeKey(quarantineKeyBase64);
    this.activeScan = null;
    this.jobs = new Map();
    this.protectionPaused = false;
    this.protectionError = null;
    this.manualMonitorConfig = null;
  }

  async init() {
    await fsp.mkdir(this.dataDirectory, { recursive: true });
    this.config = await loadJson(path.join(this.baseDirectory, 'config', 'default.json'));
    this.definitions = await loadJson(path.join(this.baseDirectory, 'definitions', 'signatures.json'));
    const packageInfo = await loadJson(path.join(this.baseDirectory, 'package.json'));
    this.version = packageInfo.version;
    this.settingsFile = path.join(this.dataDirectory, 'settings.json');
    this.stateFile = path.join(this.dataDirectory, 'state.json');
    this.settings = sanitizeSettings(await readJsonOr(this.settingsFile, DEFAULT_SETTINGS));
    this.state = sanitizeState(await readJsonOr(this.stateFile, {}));
    const quarantineDirectory = path.join(this.dataDirectory, 'quarantine');
    this.quarantine = new Quarantine(quarantineDirectory, { key: this.quarantineKey });
    await this.quarantine.init();
    let canonicalQuarantineDirectory = quarantineDirectory;
    try { canonicalQuarantineDirectory = await fsp.realpath(quarantineDirectory); }
    catch { /* the resolved vault path remains an exact, safe exclusion */ }
    this.engine = new ScanEngine({
      ...this.config,
      definitions: this.definitions,
      trustVerifier: createAuthenticodeVerifier(),
      excludePaths: [canonicalQuarantineDirectory, quarantineDirectory],
      isTransientPath: candidate => this.quarantine.isTransientPath(candidate)
    });
    this.watchService = new WatchService({
      engine: this.engine,
      quarantine: this.quarantine,
      emit: event => this.handleMonitorEvent(event),
      ...this.watchOptions
    });
    this.downloadsWatchService = new WatchService({
      engine: this.engine,
      quarantine: this.quarantine,
      emit: event => this.handleProtectionEvent(event),
      ...this.watchOptions
    });
    try { await this.startDownloadsProtection({ emitState: false }); }
    catch {
      this.protectionError = 'unavailable';
      this.emitEvent('protection-error', { message: 'Downloads protection is unavailable' });
      this.emitEvent('protection-state-changed', this.getProtectionState());
    }
    return this.getBootstrap();
  }

  async getBootstrap() {
    const quarantineInventory = await this.quarantine.list();
    const monitor = this.watchService?.session;
    return {
      version: this.version,
      definitions: { version: this.definitions.version, generatedAt: this.definitions.generatedAt },
      settings: this.settings,
      lastScanAt: this.state.lastScanAt,
      lastSummary: this.state.lastSummary,
      activity: this.state.activity.slice(0, 30),
      quarantine: quarantineInventory.items,
      quarantineCount: quarantineInventory.total,
      quarantineInventory: {
        total: quarantineInventory.total,
        truncatedCount: quarantineInventory.truncatedCount,
        corruptCount: quarantineInventory.corruptCount,
        oversizedCount: quarantineInventory.oversizedCount
      },
      protection: this.getProtectionState(),
      monitor: monitor
        ? { active: true, path: monitor.root, autoQuarantine: monitor.autoQuarantine }
        : this.manualMonitorConfig
          ? {
              active: false,
              paused: this.protectionPaused,
              pending: true,
              path: this.manualMonitorConfig.target,
              autoQuarantine: this.manualMonitorConfig.autoQuarantine
            }
          : { active: false, paused: this.protectionPaused, pending: false }
    };
  }

  async startScan({ mode, target = this.downloadsDirectory, autoQuarantine = this.settings.autoQuarantine } = {}) {
    const normalizedMode = mode === 'custom' ? 'deep' : mode;
    if (normalizedMode === 'full') return this.startFullScan({ autoQuarantine });
    if (normalizedMode === 'deep') return this.startDeepScan(target, { autoQuarantine });
    if (normalizedMode === 'quick' || target === 'quick') return this.startQuickScan({ autoQuarantine });
    if (mode === undefined) return this.startDeepScan(target, { autoQuarantine });
    throw new Error('Unknown scan mode');
  }

  async startQuickScan({ autoQuarantine = this.settings.autoQuarantine } = {}) {
    if (!await pathExists(this.downloadsDirectory)) throw new Error('Quick scan target does not exist');
    return this.startStreamingScan({
      mode: 'quick',
      target: this.downloadsDirectory,
      roots: [this.downloadsDirectory],
      autoQuarantine,
      exhaustive: false,
      maxDepth: 0,
      applyNameExclusions: true
    });
  }

  async startDeepScan(target, { autoQuarantine = this.settings.autoQuarantine } = {}) {
    const scanTarget = requireAbsolutePath(target);
    if (!await pathExists(scanTarget)) throw new Error('Scan target does not exist');
    return this.startStreamingScan({
      mode: 'deep',
      target: scanTarget,
      roots: [scanTarget],
      autoQuarantine,
      exhaustive: true,
      maxDepth: Number.POSITIVE_INFINITY,
      applyNameExclusions: false
    });
  }

  async startFullScan({ autoQuarantine = this.settings.autoQuarantine } = {}) {
    return this.startStreamingScan({
      mode: 'full',
      target: null,
      rootsProvider: this.driveRootsProvider,
      autoQuarantine,
      exhaustive: true,
      maxDepth: Number.POSITIVE_INFINITY,
      applyNameExclusions: false
    });
  }

  async startStreamingScan({
    mode,
    target,
    roots: suppliedRoots,
    rootsProvider,
    autoQuarantine,
    exhaustive,
    maxDepth,
    applyNameExclusions
  }) {
    if (this.activeScan) throw new Error('A scan is already running');
    const controller = new AbortController();
    const scanId = crypto.randomUUID();
    const startedAt = Date.now();
    const resultMap = new Map();
    const retainedResults = [];
    const retentionState = createRetentionState(retainedResults, resultMap);
    const summary = {
      scanned: 0,
      malicious: 0,
      suspicious: 0,
      errors: 0,
      skipped: 0,
      quarantined: 0,
      traversalErrors: 0,
      traversalSkipped: 0,
      linksSkipped: 0,
      rootsScanned: 0,
      durationMs: 0
    };
    let resultsTruncated = 0;
    let roots = suppliedRoots ?? [];
    let filesDiscovered = 0;
    let bytesDiscovered = 0;
    let bytesCompleted = 0;
    let lastProgressAt = 0;
    const job = { resultMap, report: null };
    this.jobs.set(scanId, job);
    trimMap(this.jobs, MAX_STORED_JOBS);
    this.activeScan = { scanId, controller, path: target, mode };
    this.emitEvent('scan-started', {
      scanId,
      mode,
      path: target,
      rootsTotal: suppliedRoots ? suppliedRoots.length : null,
      startedAt: new Date(startedAt).toISOString(),
      autoQuarantine: Boolean(autoQuarantine)
    });

    try {
      if (rootsProvider) roots = normalizeDriveRoots(await rootsProvider());
      controller.signal.throwIfAborted();
      if (!roots.length) throw new Error('No accessible local drives were found');

      for (let rootIndex = 0; rootIndex < roots.length; rootIndex++) {
        controller.signal.throwIfAborted();
        const root = roots[rootIndex];
        const discoveredBeforeRoot = filesDiscovered;
        const completedBeforeRoot = summary.scanned;
        const bytesDiscoveredBeforeRoot = bytesDiscovered;
        const bytesCompletedBeforeRoot = bytesCompleted;

        const rootTotals = await this.engine.scanPathStreaming(root, {
          concurrency: Math.min(Number(this.config.concurrency) || 1, 2),
          exhaustive,
          maxDepth,
          applyNameExclusions,
          signal: controller.signal,
          onTraversalError: error => {
            summary.traversalErrors++;
            if (summary.traversalErrors <= MAX_TRAVERSAL_EVENTS) {
              this.emitEvent('scan-traversal-error', { scanId, mode, currentRoot: root, ...error });
            }
          },
          onTraversalSkip: detail => {
            summary.traversalSkipped++;
            if (detail.reason === 'link' || detail.reason === 'outside-root') summary.linksSkipped++;
            if (summary.traversalSkipped <= MAX_TRAVERSAL_EVENTS) {
              this.emitEvent('scan-traversal-skipped', { scanId, mode, currentRoot: root, ...detail });
            }
          },
          onResult: async result => {
            summary.scanned++;
            if (result.verdict === 'malicious') summary.malicious++;
            else if (result.verdict === 'suspicious') summary.suspicious++;
            else if (result.verdict === 'error') summary.errors++;
            else if (result.verdict === 'skipped') summary.skipped++;

            const retention = retainAttentionResult(result, retentionState);
            resultsTruncated += retention.truncated;

            if (result.verdict === 'malicious' && autoQuarantine) {
              controller.signal.throwIfAborted();
              try {
                const metadata = await this.quarantine.isolate(result.path, result, { signal: controller.signal });
                summary.quarantined++;
                result.action = 'quarantined';
                result.quarantineId = metadata.id;
                this.emitEvent('quarantine-changed', {
                  action: 'isolated', scanId, resultId: result.resultId, item: metadata
                });
              } catch (error) {
                if (error.name === 'AbortError') throw error;
                result.action = 'quarantine-error';
                result.actionError = String(error.message ?? '').slice(0, 1_000);
              }
            }

            if (retention.retained) this.emitEvent('scan-detection', { scanId, mode, result });
          },
          onProgress: progress => {
            filesDiscovered = discoveredBeforeRoot + progress.filesDiscovered;
            bytesDiscovered = bytesDiscoveredBeforeRoot + progress.bytesDiscovered;
            bytesCompleted = bytesCompletedBeforeRoot + progress.bytesCompleted;
            const now = Date.now();
            if (now - lastProgressAt >= 80) {
              lastProgressAt = now;
              this.emitEvent('scan-progress', {
                scanId,
                mode,
                phase: 'scanning',
                rootsTotal: roots.length,
                rootsCompleted: rootIndex,
                currentRoot: root,
                filesDiscovered,
                completed: completedBeforeRoot + progress.completed,
                total: null,
                bytesDiscovered,
                bytesCompleted,
                malicious: summary.malicious,
                suspicious: summary.suspicious,
                threats: summary.malicious + summary.suspicious,
                errors: summary.errors + summary.traversalErrors,
                fileErrors: summary.errors,
                skipped: summary.skipped,
                traversalErrors: summary.traversalErrors,
                traversalSkipped: summary.traversalSkipped,
                linksSkipped: summary.linksSkipped,
                currentPath: progress.currentPath
              });
            }
          }
        });
        filesDiscovered = discoveredBeforeRoot + rootTotals.filesDiscovered;
        bytesDiscovered = bytesDiscoveredBeforeRoot + rootTotals.bytesDiscovered;
        bytesCompleted = bytesCompletedBeforeRoot + rootTotals.bytesCompleted;
        summary.rootsScanned++;
      }

      summary.durationMs = Date.now() - startedAt;
      const completedAt = new Date().toISOString();
      this.state.lastScanAt = completedAt;
      this.state.lastSummary = summary;
      this.addActivity({ type: 'scan', mode, at: completedAt, path: target, summary });
      const report = {
        scanId, mode, path: target, completedAt, summary,
        results: compactRetainedResults(retentionState),
        resultsTruncated
      };
      job.report = report;
      try { await this.persistState(); }
      catch {
        this.emitEvent('scan-warning', {
          scanId, mode, code: 'STATE_NOT_PERSISTED', message: 'Scan completed but its history could not be saved'
        });
      }
      this.emitEvent('scan-progress', {
        scanId,
        mode,
        phase: 'scanning',
        rootsTotal: roots.length,
        rootsCompleted: roots.length,
        currentRoot: null,
        filesDiscovered,
        completed: summary.scanned,
        total: null,
        bytesDiscovered,
        bytesCompleted,
        malicious: summary.malicious,
        suspicious: summary.suspicious,
        threats: summary.malicious + summary.suspicious,
        errors: summary.errors + summary.traversalErrors,
        fileErrors: summary.errors,
        skipped: summary.skipped,
        traversalErrors: summary.traversalErrors,
        traversalSkipped: summary.traversalSkipped,
        linksSkipped: summary.linksSkipped,
        currentPath: null
      });
      this.emitEvent('scan-completed', report);
      return report;
    } catch (error) {
      summary.durationMs = Date.now() - startedAt;
      if (error.name === 'AbortError') {
        const report = {
          scanId, mode, path: target, cancelled: true, summary,
          results: compactRetainedResults(retentionState),
          resultsTruncated
        };
        job.report = report;
        this.emitEvent('scan-cancelled', report);
        return report;
      }
      this.emitEvent('scan-error', { scanId, mode, path: target, message: error.message });
      throw error;
    } finally {
      this.activeScan = null;
    }
  }


  cancelScan(scanId) {
    if (!this.activeScan || (scanId && scanId !== this.activeScan.scanId)) return false;
    this.activeScan.controller.abort();
    return true;
  }

  async isolateResult(scanId, resultId) {
    const result = this.jobs.get(String(scanId))?.resultMap.get(String(resultId));
    if (!result) throw new Error('Unknown scan result');
    if (!['malicious', 'suspicious'].includes(result.verdict)) throw new Error('Only detected files can be quarantined');
    if (result.action === 'quarantined') return { id: result.quarantineId, alreadyIsolated: true };
    const metadata = await this.quarantine.isolate(result.path, result);
    result.action = 'quarantined';
    result.quarantineId = metadata.id;
    this.emitEvent('quarantine-changed', { action: 'isolated', scanId, resultId, item: metadata });
    return metadata;
  }

  async listQuarantine() { return this.quarantine.list(); }

  async restoreQuarantine(id, destination) {
    if (!isUuid(id)) throw new Error('Invalid quarantine identifier');
    const restoredPath = await this.quarantine.restore(String(id), destination || undefined);
    this.addActivity({ type: 'restore', at: new Date().toISOString(), path: restoredPath });
    this.emitEvent('quarantine-changed', { action: 'restored', id, path: restoredPath });
    await this.persistStateBestEffort('restore');
    return restoredPath;
  }

  async createAndScanSimulation() {
    const directory = path.join(this.dataDirectory, 'simulation', crypto.randomUUID());
    const sample = await createHarmlessSimulation(directory);
    return this.startScan({ target: sample, autoQuarantine: true });
  }

  async startMonitor(target, options = {}) {
    const config = {
      target: requireAbsolutePath(target),
      autoQuarantine: options.autoQuarantine ?? this.settings.autoQuarantine
    };
    this.manualMonitorConfig = config;
    if (this.protectionPaused) {
      const state = { active: false, paused: true, pending: true, path: config.target, autoQuarantine: config.autoQuarantine };
      this.emitEvent('monitor-changed', state);
      return state;
    }
    return this.watchService.start(config.target, { autoQuarantine: config.autoQuarantine });
  }

  async stopMonitor() {
    this.manualMonitorConfig = null;
    const state = await this.watchService.stop({ emit: false });
    const publicState = { ...state, paused: this.protectionPaused, pending: false };
    this.emitEvent('monitor-changed', publicState);
    return publicState;
  }

  getProtectionState() {
    return {
      active: !this.protectionPaused && Boolean(this.downloadsWatchService?.session),
      paused: this.protectionPaused,
      targetLabel: 'Descargas',
      autoQuarantine: Boolean(this.settings?.autoQuarantine),
      sessionOnly: true,
      error: this.protectionError
    };
  }

  async pauseProtection() {
    if (this.protectionPaused) return this.getProtectionState();
    this.protectionPaused = true;
    await Promise.all([
      this.downloadsWatchService.stop({ emit: false }),
      this.watchService.stop({ emit: false })
    ]);
    if (this.manualMonitorConfig) {
      this.emitEvent('monitor-changed', {
        active: false,
        paused: true,
        pending: true,
        path: this.manualMonitorConfig.target,
        autoQuarantine: this.manualMonitorConfig.autoQuarantine
      });
    }
    const state = this.getProtectionState();
    this.emitEvent('protection-state-changed', state);
    return state;
  }

  async resumeProtection() {
    this.protectionPaused = false;
    try {
      await this.startDownloadsProtection();
    } catch {
      this.protectionError = 'unavailable';
      this.emitEvent('protection-error', { message: 'Downloads protection is unavailable' });
    }
    if (this.manualMonitorConfig) {
      try {
        await this.watchService.start(this.manualMonitorConfig.target, {
          autoQuarantine: this.manualMonitorConfig.autoQuarantine
        });
      } catch {
        this.emitEvent('monitor-error', { message: 'The selected monitor could not be resumed' });
      }
    }
    const state = this.getProtectionState();
    this.emitEvent('protection-state-changed', state);
    return state;
  }

  async startDownloadsProtection() {
    if (this.protectionPaused) return this.getProtectionState();
    await this.downloadsWatchService.start(this.downloadsDirectory, {
      autoQuarantine: this.settings.autoQuarantine
    });
    this.protectionError = null;
    return this.getProtectionState();
  }

  async saveSettings(input) {
    const previousAutoQuarantine = this.settings.autoQuarantine;
    this.settings = sanitizeSettings({ ...this.settings, ...input });
    await writeJsonAtomic(this.settingsFile, this.settings);
    this.downloadsWatchService.setAutoQuarantine(this.settings.autoQuarantine);
    this.watchService.setAutoQuarantine(this.settings.autoQuarantine);
    if (this.manualMonitorConfig && previousAutoQuarantine !== this.settings.autoQuarantine) {
      this.manualMonitorConfig.autoQuarantine = this.settings.autoQuarantine;
    }
    this.emitEvent('settings-changed', this.settings);
    if (previousAutoQuarantine !== this.settings.autoQuarantine) {
      this.emitEvent('protection-state-changed', this.getProtectionState());
    }
    return this.settings;
  }

  async shutdown() {
    if (this.activeScan) this.activeScan.controller.abort();
    await Promise.all([
      this.watchService?.stop({ emit: false }),
      this.downloadsWatchService?.stop({ emit: false })
    ]);
  }

  handleMonitorEvent(event) {
    if (event.type === 'monitor-result' && event.payload.result.verdict !== 'clean') {
      const result = event.payload.result;
      this.addActivity({
        type: 'monitor-detection', at: new Date().toISOString(), path: result.path,
        verdict: result.verdict, score: result.score
      });
      void this.persistStateBestEffort('monitor');
    }
    this.emit(event);
  }

  handleProtectionEvent(event) {
    if (event.type === 'monitor-changed') {
      this.emitEvent('protection-state-changed', this.getProtectionState());
      return;
    }
    if (event.type === 'monitor-result') {
      const result = event.payload.result;
      if (result.verdict !== 'clean') {
        this.addActivity({
          type: 'protection-detection', at: new Date().toISOString(), path: result.path,
          verdict: result.verdict, score: result.score
        });
        void this.persistStateBestEffort('protection');
        this.emitEvent('protection-detection', { result });
      }
      if (result.action === 'quarantined') {
        this.emitEvent('quarantine-changed', {
          action: 'isolated', id: result.quarantineId, path: result.path
        });
      }
      return;
    }
    if (event.type === 'monitor-warning') {
      this.emitEvent('protection-warning', { message: 'Protection queue is full; a later scan is recommended' });
      return;
    }
    if (event.type === 'monitor-error') {
      this.protectionError = 'unavailable';
      this.emitEvent('protection-error', { message: 'Downloads protection encountered an error' });
      this.emitEvent('protection-state-changed', this.getProtectionState());
    }
  }

  addActivity(entry) {
    this.state.activity = [entry, ...this.state.activity].slice(0, 100);
  }

  async persistState() { await writeJsonAtomic(this.stateFile, this.state); }
  async persistStateBestEffort(context) {
    try {
      await this.persistState();
      return true;
    } catch {
      this.emitEvent('scan-warning', {
        code: 'STATE_NOT_PERSISTED',
        context,
        message: 'Activity completed but its history could not be saved'
      });
      return false;
    }
  }
  emitEvent(type, payload) { this.emit({ type, payload }); }
}

function sanitizeSettings(input = {}) {
  return {
    theme: ['system', 'light', 'dark'].includes(input.theme) ? input.theme : DEFAULT_SETTINGS.theme,
    autoQuarantine: typeof input.autoQuarantine === 'boolean' ? input.autoQuarantine : DEFAULT_SETTINGS.autoQuarantine,
    notifications: typeof input.notifications === 'boolean' ? input.notifications : DEFAULT_SETTINGS.notifications,
    checkUpdates: typeof input.checkUpdates === 'boolean' ? input.checkUpdates : DEFAULT_SETTINGS.checkUpdates,
    updateChannel: ['stable', 'beta'].includes(input.updateChannel) ? input.updateChannel : DEFAULT_SETTINGS.updateChannel,
    launchAtStartup: typeof input.launchAtStartup === 'boolean' ? input.launchAtStartup : DEFAULT_SETTINGS.launchAtStartup
  };
}

function sanitizeState(input = {}) {
  return {
    lastScanAt: typeof input.lastScanAt === 'string' ? input.lastScanAt : null,
    lastSummary: input.lastSummary && typeof input.lastSummary === 'object' ? input.lastSummary : null,
    activity: Array.isArray(input.activity) ? input.activity.slice(0, 100) : []
  };
}

function createRetentionState(results, resultMap) {
  return {
    results,
    resultMap,
    slotsByPriority: Array.from({ length: 5 }, () => new Set()),
    bytesByPriority: new Array(5).fill(0),
    bytesByIndex: [],
    freeSlots: new Set(),
    retainedCount: 0,
    retainedBytes: 0
  };
}

function retainAttentionResult(result, state) {
  const priority = RESULT_PRIORITY[result.verdict] ?? 0;
  if (!priority) return { retained: false, truncated: 0 };
  const resultBytes = estimateResultBytes(result);
  if (resultBytes > MAX_RETAINED_RESULT_BYTES) return { retained: false, truncated: 1 };

  const needsCount = Math.max(0, state.retainedCount + 1 - MAX_RETAINED_RESULTS);
  const needsBytes = Math.max(0, state.retainedBytes + resultBytes - MAX_RETAINED_RESULT_BYTES);
  let lowerCount = 0;
  let lowerBytes = 0;
  for (let candidatePriority = 1; candidatePriority < priority; candidatePriority++) {
    lowerCount += state.slotsByPriority[candidatePriority].size;
    lowerBytes += state.bytesByPriority[candidatePriority];
  }
  if (lowerCount < needsCount || lowerBytes < needsBytes) {
    return { retained: false, truncated: needsCount || needsBytes ? 1 : 0 };
  }

  let evictedCount = 0;
  while (
    state.retainedCount + 1 > MAX_RETAINED_RESULTS
    || state.retainedBytes + resultBytes > MAX_RETAINED_RESULT_BYTES
  ) {
    let victimPriority = 0;
    for (let candidatePriority = 1; candidatePriority < priority; candidatePriority++) {
      if (state.slotsByPriority[candidatePriority].size) {
        victimPriority = candidatePriority;
        break;
      }
    }
    if (!victimPriority) return { retained: false, truncated: Math.max(1, evictedCount) };
    evictRetainedResult(state, victimPriority);
    evictedCount++;
  }

  result.resultId = crypto.randomUUID();
  const available = state.freeSlots.values().next();
  const index = available.done ? state.results.length : available.value;
  if (!available.done) state.freeSlots.delete(index);
  if (index === state.results.length) state.results.push(result);
  else state.results[index] = result;
  state.bytesByIndex[index] = resultBytes;
  state.slotsByPriority[priority].add(index);
  state.bytesByPriority[priority] += resultBytes;
  state.retainedCount++;
  state.retainedBytes += resultBytes;
  if (result.verdict === 'malicious' || result.verdict === 'suspicious') {
    state.resultMap.set(result.resultId, result);
  }
  return { retained: true, truncated: evictedCount };
}

function evictRetainedResult(state, priority) {
  const slots = state.slotsByPriority[priority];
  const index = slots.values().next().value;
  slots.delete(index);
  const evicted = state.results[index];
  const bytes = state.bytesByIndex[index] ?? 0;
  if (evicted?.resultId) state.resultMap.delete(evicted.resultId);
  state.results[index] = null;
  state.bytesByIndex[index] = 0;
  state.freeSlots.add(index);
  state.retainedCount--;
  state.retainedBytes -= bytes;
  state.bytesByPriority[priority] -= bytes;
}

function compactRetainedResults(state) {
  return state.results.filter(Boolean);
}

function estimateResultBytes(result) {
  let bytes = 1_024;
  for (const value of [
    result.path, result.sha256, result.error, result.action,
    result.actionError, result.quarantineId
  ]) {
    if (typeof value === 'string') bytes += value.length * 2;
  }
  if (Array.isArray(result.findings)) {
    for (const finding of result.findings) {
      bytes += 192;
      if (typeof finding?.id === 'string') bytes += finding.id.length * 2;
      if (typeof finding?.description === 'string') bytes += finding.description.length * 2;
    }
  }
  return bytes;
}

function requireAbsolutePath(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) throw new Error('Target must be an absolute path');
  return path.resolve(value);
}

function isUuid(value) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value)); }

function trimMap(map, maximum) {
  while (map.size > maximum) map.delete(map.keys().next().value);
}

function normalizeDriveRoots(value) {
  if (!Array.isArray(value)) throw new Error('Drive roots provider returned an invalid value');
  const roots = [];
  const seen = new Set();
  for (const item of value.slice(0, 32)) {
    if (typeof item !== 'string' || !path.isAbsolute(item)) continue;
    const root = path.resolve(item);
    const key = process.platform === 'win32' ? root.toLowerCase() : root;
    if (!seen.has(key)) {
      seen.add(key);
      roots.push(root);
    }
  }
  return roots;
}

function decodeKey(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw new Error('Invalid protected quarantine key');
  }
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('Invalid protected quarantine key');
  return key;
}

async function readJsonOr(file, fallback) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT' && error.name !== 'SyntaxError') throw error; return structuredClone(fallback); }
}

async function writeJsonAtomic(file, value) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  await fsp.writeFile(temporary, JSON.stringify(value, null, 2), { flag: 'wx' });
  await fsp.rename(temporary, file);
}
