import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { ScanEngine } from './engine.mjs';
import { Quarantine } from './quarantine.mjs';
import { createHarmlessSimulation } from './simulator.mjs';
import { WatchService } from './watch-service.mjs';
import { discoverWindowsDriveRoots } from './drive-roots.mjs';
import { createAuthenticodeVerifier } from './authenticode.mjs';
import { ScanReportWriter } from './report-writer.mjs';
import { NetworkAuditor, writeNetworkReport } from './network-audit.mjs';
import { EDRAuditor, writeEdrReport } from './edr-audit.mjs';
import { NetworkProtector } from './network-protection.mjs';
import { ExposureAuditor, writeExposureReport } from './exposure-audit.mjs';
import { SelfProtectionAuditor, writeSelfProtectionReport } from './self-protection-audit.mjs';
import { DefinitionUpdateStore } from './definition-updater.mjs';
import { DefinitionFeedService } from './definition-feed-service.mjs';
import { ThreatIntelStore } from './threat-intel-store.mjs';
import { loadJson, pathExists } from './util.mjs';
import { validateDefinitions } from './definition-security.mjs';
import { RansomwareAudit } from './ransomware-audit.mjs';

const DEFAULT_SETTINGS = Object.freeze({
  theme: 'system',
  autoQuarantine: false,
  notifications: true,
  checkUpdates: true,
  updateChannel: 'stable',
  launchAtStartup: true,
  scheduledScanEnabled: false,
  scheduledScanMode: 'quick',
  scheduledScanHour: 3,
  skipScheduledScanOnBattery: true,
  ransomwareAuditEnabled: false,
  networkProtectionMode: 'audit',
  reputationSharingEnabled: false
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
    protectedDirectories = [],
    quarantineKeyBase64,
    driveRootsProvider = discoverWindowsDriveRoots,
    watchOptions = {},
    edrOptions = {},
    networkProtectionOptions = {},
    exposureOptions = {},
    selfProtectionOptions = {},
    definitionUpdateOptions = {},
    definitionFeedOptions = {},
    threatIntelOptions = {},
    statePersistenceDelayMs = 750,
    emit = () => {}
  }) {
    this.baseDirectory = path.resolve(baseDirectory);
    this.dataDirectory = path.resolve(dataDirectory);
    this.downloadsDirectory = path.resolve(downloadsDirectory);
    this.protectedDirectories = normalizeProtectedDirectories(protectedDirectories);
    this.emit = emit;
    this.driveRootsProvider = driveRootsProvider;
    this.watchOptions = watchOptions;
    this.edrOptions = edrOptions;
    this.networkProtectionOptions = networkProtectionOptions;
    this.exposureOptions = exposureOptions;
    this.selfProtectionOptions = selfProtectionOptions;
    this.definitionUpdateOptions = definitionUpdateOptions;
    this.definitionFeedOptions = definitionFeedOptions;
    this.threatIntelOptions = threatIntelOptions;
    this.statePersistenceDelayMs = Math.max(50, Math.min(5_000, Number(statePersistenceDelayMs) || 750));
    this.quarantineKey = decodeKey(quarantineKeyBase64);
    this.activeScan = null;
    this.jobs = new Map();
    this.protectionPaused = false;
    this.protectionError = null;
    this.manualMonitorConfig = null;
    this.persistenceQueue = Promise.resolve();
    this.persistenceTimer = null;
    this.persistenceContexts = new Set();
    this.scheduledPersistenceFlush = null;
  }

  async init() {
    await fsp.mkdir(this.dataDirectory, { recursive: true });
    this.config = await loadJson(path.join(this.baseDirectory, 'config', 'default.json'));
    const definitionTrust = await readJsonOr(path.join(this.baseDirectory, 'config', 'definition-keys.json'), {});
    this.definitionUpdateStore = new DefinitionUpdateStore({
      baseDirectory: this.baseDirectory,
      dataDirectory: this.dataDirectory,
      publicKeys: definitionTrust.keys,
      ...this.definitionUpdateOptions
    });
    await this.definitionUpdateStore.init();
    this.definitions = validateDefinitions(this.definitionUpdateStore.currentDefinitions);
    const definitionFeedConfig = await readJsonOr(path.join(this.baseDirectory, 'config', 'definition-feed.json'), {});
    this.definitionFeedService = new DefinitionFeedService({
      ...this.definitionFeedOptions,
      dataDirectory: this.dataDirectory,
      config: { ...definitionFeedConfig, ...(this.definitionFeedOptions.config ?? {}) },
      applyEnvelope: envelope => this.applyDefinitionBundle(envelope),
      isBusy: () => Boolean(this.activeScan)
    });
    await this.definitionFeedService.init();
    const threatIntelConfig = await readJsonOr(path.join(this.baseDirectory, 'config', 'threat-intel.json'), {});
    this.threatIntelStore = new ThreatIntelStore({
      ...this.threatIntelOptions,
      dataDirectory: this.dataDirectory,
      config: { ...threatIntelConfig, ...(this.threatIntelOptions.config ?? {}) }
    });
    await this.threatIntelStore.init();
    this.networkIndicators = await loadJson(path.join(this.baseDirectory, 'definitions', 'network-indicators.json'));
    this.applicationPolicies = await readJsonOr(path.join(this.baseDirectory, 'definitions', 'application-policies.json'), {});
    const packageInfo = await loadJson(path.join(this.baseDirectory, 'package.json'));
    this.version = packageInfo.version;
    this.settingsFile = path.join(this.dataDirectory, 'settings.json');
    this.stateFile = path.join(this.dataDirectory, 'state.json');
    this.reportsDirectory = path.join(this.dataDirectory, 'reports');
    this.networkAuditor = new NetworkAuditor({ indicators: this.networkIndicators });
    this.edrAuditor = new EDRAuditor(this.edrOptions);
    this.networkProtector = new NetworkProtector(this.networkProtectionOptions);
    this.exposureAuditor = new ExposureAuditor({ ...this.exposureOptions, policies: this.applicationPolicies });
    this.selfProtectionAuditor = new SelfProtectionAuditor({ baseDirectory: this.baseDirectory, ...this.selfProtectionOptions });
    this.settings = sanitizeSettings(await readJsonOr(this.settingsFile, DEFAULT_SETTINGS));
    this.state = sanitizeState(await readJsonOr(this.stateFile, {}));
    if (this.state.networkProtection) this.networkProtector.state = { ...this.networkProtector.status(), ...this.state.networkProtection };
    this.ransomwareAudit = new RansomwareAudit({
      roots: this.protectedDirectories,
      emit: event => this.handleRansomwareEvent(event)
    });
    this.recoveredOperation = this.state.activeOperation;
    if (this.recoveredOperation) {
      this.addActivity({ type: 'recovery', at: new Date().toISOString(), operation: this.recoveredOperation });
      this.state.activeOperation = null;
      await this.persistStateBestEffort('startup-recovery');
    }
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
      excludePaths: [canonicalQuarantineDirectory, quarantineDirectory, this.reportsDirectory, this.stateFile, this.settingsFile, path.join(this.dataDirectory, 'schedule-state.json')],
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
    if (this.settings.ransomwareAuditEnabled) await this.ransomwareAudit.start();
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
    const ransomwareAudit = this.getRansomwareAuditState();
    return {
      version: this.version,
      definitions: { version: this.definitions.version, generatedAt: this.definitions.generatedAt, updates: this.getDefinitionUpdateState() },
      threatIntel: { status: this.getThreatIntelState(), latest: this.state.latestThreatIntel },
      settings: this.settings,
      lastScanAt: this.state.lastScanAt,
      lastSummary: this.state.lastSummary,
      activity: this.state.activity.slice(0, 30),
      reportAvailable: Boolean(await Promise.all([this.getLatestReport('json'), this.getLatestReport('csv')]).catch(() => null)),
      network: this.state.latestNetworkReport?.summary ? { ...this.state.latestNetworkReport, reportAvailable: true } : null,
      networkProtection: this.getNetworkProtectionState(),
      exposure: this.state.latestExposureReport?.summary ? { ...this.state.latestExposureReport, reportAvailable: true } : null,
      integrity: this.state.latestIntegrityReport?.summary ? { ...this.state.latestIntegrityReport, reportAvailable: true } : null,
      edr: this.state.latestEdrReport?.summary ? { ...this.state.latestEdrReport, reportAvailable: true } : null,
      health: {
        status: this.protectionError || this.lastPersistenceError || this.recoveredOperation || (this.settings.ransomwareAuditEnabled && ransomwareAudit.rootsObserved < ransomwareAudit.rootsConfigured) ? 'degraded' : 'healthy',
        authenticatedWorkerIpc: true,
        protectionAvailable: !this.protectionError,
        statePersistenceAvailable: !this.lastPersistenceError,
        recoveredInterruptedOperation: Boolean(this.recoveredOperation),
        ransomwareAuditAvailable: !this.settings.ransomwareAuditEnabled || ransomwareAudit.rootsObserved > 0,
        edrAuditAvailable: Boolean(this.state.latestEdrReport?.available || process.platform === 'win32'),
        networkProtectionAvailable: process.platform === 'win32',
        exposureAuditAvailable: process.platform === 'win32',
        selfProtectionAvailable: Boolean(this.state.latestIntegrityReport?.available || this.selfProtectionAuditor)
      },
      quarantine: quarantineInventory.items,
      quarantineCount: quarantineInventory.total,
      quarantineInventory: {
        total: quarantineInventory.total,
        truncatedCount: quarantineInventory.truncatedCount,
        corruptCount: quarantineInventory.corruptCount,
        oversizedCount: quarantineInventory.oversizedCount
      },
      protection: this.getProtectionState(),
      performance: this.getPerformanceState(),
      ransomwareAudit,
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
    const performanceBefore = this.engine.getPerformanceMetrics();
    const scanConcurrency = resolveScanConcurrency(this.config.concurrency);
    const previousReport = this.state.latestReport;
    const reportWriter = await new ScanReportWriter({ directory: this.reportsDirectory, scanId, mode, target, startedAt }).init();
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
    this.state.activeOperation = { kind: 'scan', scanId, mode, startedAt: new Date(startedAt).toISOString() };
    await this.persistStateBestEffort('scan-start');
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
          concurrency: scanConcurrency,
          exhaustive,
          maxDepth,
          applyNameExclusions,
          signal: controller.signal,
          onTraversalError: error => {
            summary.traversalErrors++;
            const result = {
              path: error.path,
              verdict: 'error', score: 0, findings: [],
              error: error.error || 'Path could not be accessed',
              detailType: 'traversal-error'
            };
            const retention = retainAttentionResult(result, retentionState);
            resultsTruncated += retention.truncated;
            void reportWriter.append(result);
            if (summary.traversalErrors <= MAX_TRAVERSAL_EVENTS) {
              this.emitEvent('scan-traversal-error', { scanId, mode, currentRoot: root, ...error });
            }
          },
          onTraversalSkip: detail => {
            summary.traversalSkipped++;
            if (detail.reason === 'link' || detail.reason === 'outside-root') summary.linksSkipped++;
            const result = {
              path: detail.path,
              verdict: 'skipped', score: 0,
              findings: [{ id: `traversal.${detail.reason || 'skipped'}`, description: `Not scanned: ${detail.reason || 'safe traversal policy'}`, score: 0 }],
              detailType: 'traversal-skip'
            };
            const retention = retainAttentionResult(result, retentionState);
            resultsTruncated += retention.truncated;
            void reportWriter.append(result);
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

            await reportWriter.append(result);

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
      summary.performance = performanceDelta(performanceBefore, this.engine.getPerformanceMetrics());
      summary.performance.concurrency = scanConcurrency;
      const completedAt = new Date().toISOString();
      this.state.lastScanAt = completedAt;
      this.state.lastSummary = summary;
      this.addActivity({ type: 'scan', mode, at: completedAt, path: target, summary });
      const report = {
        scanId, mode, path: target, completedAt, summary,
        results: compactRetainedResults(retentionState),
        resultsTruncated
      };
      const fullReport = await reportWriter.finalize({ completedAt, summary, resultsTruncated });
      report.reportAvailable = Boolean(fullReport);
      if (fullReport) {
        this.state.latestReport = fullReport;
        await this.removeReportFiles(previousReport);
      }
      else this.emitEvent('scan-warning', { scanId, mode, code: 'REPORT_NOT_PERSISTED', message: 'The full scan report could not be saved' });
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
      summary.performance = performanceDelta(performanceBefore, this.engine.getPerformanceMetrics());
      summary.performance.concurrency = scanConcurrency;
      if (error.name === 'AbortError') {
        const completedAt = new Date().toISOString();
        const report = {
          scanId, mode, path: target, completedAt, cancelled: true, summary,
          results: compactRetainedResults(retentionState),
          resultsTruncated
        };
        const fullReport = await reportWriter.finalize({ completedAt, cancelled: true, summary, resultsTruncated });
        report.reportAvailable = Boolean(fullReport);
        if (fullReport) {
          this.state.latestReport = fullReport;
          await this.removeReportFiles(previousReport);
        }
        if (fullReport) await this.persistStateBestEffort('cancelled-scan-report');
        job.report = report;
        this.emitEvent('scan-cancelled', report);
        return report;
      }
      await reportWriter.abort();
      this.emitEvent('scan-error', { scanId, mode, path: target, message: error.message });
      throw error;
    } finally {
      this.activeScan = null;
      this.state.activeOperation = null;
      await this.persistStateBestEffort('scan-finished');
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

  async getLatestReport(format) {
    if (!['json', 'csv'].includes(format)) throw new Error('Unknown report format');
    const report = this.state.latestReport;
    const fileName = format === 'json' ? report?.jsonFile : report?.csvFile;
    if (typeof fileName !== 'string' || path.basename(fileName) !== fileName) throw new Error('No complete report is available');
    const reportPath = path.join(this.reportsDirectory, fileName);
    if (!await pathExists(reportPath)) throw new Error('The complete report is no longer available');
    return { path: reportPath, format, completedAt: report.completedAt, count: report.count };
  }

  async runNetworkAudit() {
    const previous = this.state.latestNetworkReport;
    const report = await this.networkAuditor.audit();
    const files = await writeNetworkReport(this.reportsDirectory, report);
    this.state.latestNetworkReport = {
      completedAt: report.completedAt,
      summary: report.summary,
      windowsSecurity: report.windowsSecurity,
      events: report.events.slice(0, 500),
      jsonFile: path.basename(files.json),
      csvFile: path.basename(files.csv)
    };
    this.addActivity({ type: 'network-audit', at: report.completedAt, summary: report.summary });
    await this.persistStateBestEffort('network-audit');
    if (previous) await this.removeReportFiles(previous);
    return { ...report, reportAvailable: true, protection: this.getNetworkProtectionState() };
  }

  getNetworkProtectionState() {
    return { ...this.networkProtector?.status(), mode: this.settings?.networkProtectionMode ?? 'audit' };
  }

  async applyNetworkProtection() {
    if (this.settings.networkProtectionMode !== 'block') throw new Error('Activa primero el modo de bloqueo reversible.');
    const result = await this.networkProtector.apply(this.networkIndicators);
    this.state.networkProtection = result;
    this.addActivity({ type: 'network-protection', at: result.lastChangedAt, action: result.active ? 'applied' : 'not-applied', summary: { addressesBlocked: result.addressesBlocked, domainsPending: result.domainsPending } });
    await this.persistStateBestEffort('network-protection');
    return this.getNetworkProtectionState();
  }

  async removeNetworkProtection() {
    const result = await this.networkProtector.remove();
    this.state.networkProtection = result;
    this.addActivity({ type: 'network-protection', at: result.lastChangedAt, action: 'removed', summary: { addressesBlocked: 0, domainsPending: 0 } });
    await this.persistStateBestEffort('network-protection-remove');
    return this.getNetworkProtectionState();
  }

  async getLatestNetworkReport(format) {
    if (!['json', 'csv'].includes(format)) throw new Error('Unknown network report format');
    const report = this.state.latestNetworkReport;
    const fileName = format === 'json' ? report?.jsonFile : report?.csvFile;
    if (typeof fileName !== 'string' || path.basename(fileName) !== fileName) throw new Error('No network report is available');
    const reportPath = path.join(this.reportsDirectory, fileName);
    if (!await pathExists(reportPath)) throw new Error('The network report is no longer available');
    return { path: reportPath, format, completedAt: report.completedAt, count: report.summary?.connections ?? 0 };
  }

  async runExposureAudit() {
    const previous = this.state.latestExposureReport;
    const report = await this.exposureAuditor.audit();
    const files = await writeExposureReport(this.reportsDirectory, report);
    this.state.latestExposureReport = sanitizeExposureReport({ ...report, jsonFile: path.basename(files.json), csvFile: path.basename(files.csv) });
    this.addActivity({ type: 'exposure-audit', at: report.completedAt, summary: report.summary });
    await this.persistStateBestEffort('exposure-audit');
    if (previous) await this.removeReportFiles(previous);
    return { ...report, jsonFile: path.basename(files.json), csvFile: path.basename(files.csv), reportAvailable: true };
  }

  async runIntegrityAudit() {
    const previous = this.state.latestIntegrityReport;
    const report = await this.selfProtectionAuditor.audit();
    const files = await writeSelfProtectionReport(this.reportsDirectory, report);
    this.state.latestIntegrityReport = sanitizeIntegrityReport({ ...report, jsonFile: path.basename(files.json), csvFile: path.basename(files.csv) });
    this.addActivity({ type: 'integrity-audit', at: report.completedAt, summary: report.summary });
    await this.persistStateBestEffort('integrity-audit');
    if (previous) await this.removeReportFiles(previous);
    return { ...report, jsonFile: path.basename(files.json), csvFile: path.basename(files.csv), reportAvailable: true };
  }

  async getLatestIntegrityReport(format) {
    if (!['json', 'csv'].includes(format)) throw new Error('Unknown integrity report format');
    const report = this.state.latestIntegrityReport;
    const fileName = format === 'json' ? report?.jsonFile : report?.csvFile;
    if (typeof fileName !== 'string' || path.basename(fileName) !== fileName) throw new Error('No integrity report is available');
    const reportPath = path.join(this.reportsDirectory, fileName);
    if (!await pathExists(reportPath)) throw new Error('The integrity report is no longer available');
    return { path: reportPath, format, completedAt: report.completedAt, count: report.summary?.total ?? 0 };
  }

  getDefinitionUpdateState() {
    const status = this.definitionUpdateStore?.status() ?? {
      schemaVersion: 1, currentVersion: this.definitions?.version ?? 0, bundledVersion: this.definitions?.version ?? 0,
      source: 'bundled', signature: { status: 'bundled', keyId: null }, rollbackAvailable: false,
      lastAppliedAt: null, lastRollbackAt: null, lastError: null, updateChannelConfigured: false, networkEnabled: false
    };
    return { ...status, feed: this.definitionFeedService?.status() ?? null };
  }

  async applyDefinitionBundle(envelope) {
    if (this.activeScan) throw operationError('SCAN_BUSY', 'Espera a que termine el análisis antes de actualizar las definiciones.');
    const result = await this.definitionUpdateStore.applyEnvelope(envelope);
    try {
      this.definitions = this.definitionUpdateStore.currentDefinitions;
      this.engine.replaceDefinitions(this.definitions);
    } catch (error) {
      await this.definitionUpdateStore.rollback().catch(() => {});
      throw error;
    }
    this.addActivity({ type: 'definitions-update', at: result.lastAppliedAt, version: result.currentVersion, source: result.source });
    await this.persistStateBestEffort('definitions-update');
    this.emitEvent('definitions-changed', this.getDefinitionUpdateState());
    return this.getDefinitionUpdateState();
  }

  async rollbackDefinitions() {
    if (this.activeScan) throw operationError('SCAN_BUSY', 'Espera a que termine el análisis antes de restaurar las definiciones.');
    const result = await this.definitionUpdateStore.rollback();
    this.definitions = this.definitionUpdateStore.currentDefinitions;
    this.engine.replaceDefinitions(this.definitions);
    this.addActivity({ type: 'definitions-rollback', at: result.lastRollbackAt, version: result.currentVersion, source: result.source });
    await this.persistStateBestEffort('definitions-rollback');
    this.emitEvent('definitions-changed', this.getDefinitionUpdateState());
    return this.getDefinitionUpdateState();
  }

  async checkDefinitionFeed({ force = false } = {}) {
    if (this.activeScan) return { ...this.getDefinitionUpdateState(), result: 'busy' };
    const result = await this.definitionFeedService.check({ force });
    return { ...this.getDefinitionUpdateState(), feedResult: result.result, feedVersion: result.version ?? null };
  }

  getThreatIntelState() {
    const status = this.threatIntelStore?.status() ?? {
      schemaVersion: 1, cacheEntries: 0, cacheMaxEntries: 10_000, ttlMs: 86_400_000,
      lastLookupAt: null, providers: {}, networkEnabled: false, fileUploadEnabled: false
    };
    return { ...status, networkEnabled: this.settings?.reputationSharingEnabled === true, fileUploadEnabled: false };
  }

  async queryThreatIntel(sha256, { force = false } = {}) {
    if (!this.settings.reputationSharingEnabled) {
      throw operationError('REPUTATION_NOT_ENABLED', 'Activa primero «Permitir consultas de reputación» en Ajustes.');
    }
    const result = await this.threatIntelStore.lookupSha256(sha256, { allowNetwork: true, force });
    this.state.latestThreatIntel = result;
    this.addActivity({
      type: 'threat-intel-lookup',
      at: result.queriedAt,
      sha256: result.sha256,
      verdict: result.verdict,
      providers: result.sources.filter(source => source.status === 'match').map(source => source.provider).slice(0, 8)
    });
    await this.persistStateBestEffort('threat-intel-lookup');
    this.emitEvent('threat-intel-result', result);
    return result;
  }

  async getLatestExposureReport(format) {
    if (!['json', 'csv'].includes(format)) throw new Error('Unknown exposure report format');
    const report = this.state.latestExposureReport;
    const fileName = format === 'json' ? report?.jsonFile : report?.csvFile;
    if (typeof fileName !== 'string' || path.basename(fileName) !== fileName) throw new Error('No exposure report is available');
    const reportPath = path.join(this.reportsDirectory, fileName);
    if (!await pathExists(reportPath)) throw new Error('The exposure report is no longer available');
    return { path: reportPath, format, completedAt: report.completedAt, count: report.summary?.applications ?? 0 };
  }

  async runEdrAudit() {
    const previous = this.state.latestEdrReport;
    const report = await this.edrAuditor.audit({
      networkReport: this.state.latestNetworkReport,
      history: this.state.activity,
      ransomwareAlerts: this.state.ransomwareAlerts
    });
    const files = await writeEdrReport(this.reportsDirectory, report);
    this.state.latestEdrReport = sanitizeEdrReport({ ...report, jsonFile: path.basename(files.json) });
    this.addActivity({ type: 'edr-audit', at: report.completedAt, summary: report.summary });
    await this.persistStateBestEffort('edr-audit');
    if (previous) await this.removeReportFiles(previous);
    return { ...report, jsonFile: path.basename(files.json), reportAvailable: true };
  }

  async getLatestEdrReport() {
    const report = this.state.latestEdrReport;
    if (!report || typeof report.jsonFile !== 'string' || path.basename(report.jsonFile) !== report.jsonFile) throw new Error('No EDR report is available');
    const reportPath = path.join(this.reportsDirectory, report.jsonFile);
    if (!await pathExists(reportPath)) throw new Error('The EDR report is no longer available');
    return { path: reportPath, format: 'json', completedAt: report.completedAt, count: report.summary?.timelineEvents ?? 0 };
  }

  async removeReportFiles(report) {
    if (!report || typeof report !== 'object') return;
    const names = [report.jsonFile, report.csvFile].filter(name =>
      typeof name === 'string' && path.basename(name) === name
    );
    await Promise.allSettled(names.map(name => fsp.rm(path.join(this.reportsDirectory, name), { force: true })));
  }

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
      this.watchService.stop({ emit: false }),
      this.ransomwareAudit.stop()
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
    this.emitEvent('ransomware-audit-state', this.getRansomwareAuditState());
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
    if (this.settings.ransomwareAuditEnabled) await this.ransomwareAudit.start();
    const state = this.getProtectionState();
    this.emitEvent('ransomware-audit-state', this.getRansomwareAuditState());
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
    const previousRansomwareAudit = this.settings.ransomwareAuditEnabled;
    const previousNetworkMode = this.settings.networkProtectionMode;
    this.settings = sanitizeSettings({ ...this.settings, ...input });
    await writeJsonAtomic(this.settingsFile, this.settings);
    this.downloadsWatchService.setAutoQuarantine(this.settings.autoQuarantine);
    this.watchService.setAutoQuarantine(this.settings.autoQuarantine);
    if (this.manualMonitorConfig && previousAutoQuarantine !== this.settings.autoQuarantine) {
      this.manualMonitorConfig.autoQuarantine = this.settings.autoQuarantine;
    }
    if (previousRansomwareAudit !== this.settings.ransomwareAuditEnabled) {
      if (this.settings.ransomwareAuditEnabled && !this.protectionPaused) await this.ransomwareAudit.start();
      else await this.ransomwareAudit.stop({ removeCanaries: !this.settings.ransomwareAuditEnabled });
      this.emitEvent('ransomware-audit-state', this.getRansomwareAuditState());
    }
    if (previousNetworkMode !== this.settings.networkProtectionMode) {
      this.state.networkProtection = { ...this.getNetworkProtectionState(), mode: this.settings.networkProtectionMode };
      await this.persistStateBestEffort('network-protection-mode');
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
      this.downloadsWatchService?.stop({ emit: false }),
      this.ransomwareAudit?.stop()
    ]);
    do {
      await this.flushScheduledPersistence();
    } while (this.persistenceContexts.size);
    await this.persistenceQueue.catch(() => {});
  }

  handleMonitorEvent(event) {
    if (event.type === 'monitor-result' && event.payload.result.verdict !== 'clean') {
      const result = event.payload.result;
      this.addActivity({
        type: 'monitor-detection', at: new Date().toISOString(), path: result.path,
        verdict: result.verdict, score: result.score
      });
      this.scheduleStatePersistence('monitor');
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
        this.scheduleStatePersistence('protection');
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

  handleRansomwareEvent(event) {
    if (event.type !== 'ransomware-audit-alert') return;
    const alert = event.payload;
    this.state.ransomwareAlerts = [alert, ...this.state.ransomwareAlerts].slice(0, 100);
    this.addActivity({
      type: 'ransomware-audit', at: alert.at, kind: alert.kind,
      severity: alert.severity, rootLabel: alert.rootLabel
    });
    this.emit(event);
    this.scheduleStatePersistence('ransomware-audit');
  }

  getRansomwareAuditState() {
    const status = this.ransomwareAudit.status();
    return { ...status, configured: this.settings.ransomwareAuditEnabled, paused: this.protectionPaused, recentAlerts: this.state.ransomwareAlerts.slice(0, 20) };
  }

  addActivity(entry) {
    this.state.activity = [entry, ...this.state.activity].slice(0, 100);
  }

  getPerformanceState() {
    const memory = process.memoryUsage();
    return {
      engine: this.engine.getPerformanceMetrics(),
      protection: this.downloadsWatchService.status(),
      monitor: this.watchService.status(),
      runtime: { rssBytes: memory.rss, heapUsedBytes: memory.heapUsed }
    };
  }

  scheduleStatePersistence(context) {
    this.persistenceContexts.add(context || 'background');
    if (this.persistenceTimer || this.scheduledPersistenceFlush) return;
    this.persistenceTimer = setTimeout(() => {
      this.persistenceTimer = null;
      this.scheduledPersistenceFlush = this.flushScheduledPersistence()
        .finally(() => {
          this.scheduledPersistenceFlush = null;
          if (this.persistenceContexts.size) this.scheduleStatePersistence('queued');
        });
    }, this.statePersistenceDelayMs);
    this.persistenceTimer.unref?.();
  }

  async flushScheduledPersistence() {
    if (this.persistenceTimer) {
      clearTimeout(this.persistenceTimer);
      this.persistenceTimer = null;
    }
    if (this.scheduledPersistenceFlush) return this.scheduledPersistenceFlush;
    if (!this.persistenceContexts.size) return true;
    const context = [...this.persistenceContexts].sort().join('+');
    this.persistenceContexts.clear();
    return this.persistStateBestEffort(context);
  }

  async persistState() {
    const snapshot = structuredClone(this.state);
    const operation = this.persistenceQueue.catch(() => {}).then(() => writeJsonAtomic(this.stateFile, snapshot));
    this.persistenceQueue = operation;
    await operation;
  }
  async persistStateBestEffort(context) {
    try {
      await this.persistState();
      this.lastPersistenceError = null;
      return true;
    } catch {
      this.lastPersistenceError = context || 'unknown';
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
    launchAtStartup: typeof input.launchAtStartup === 'boolean' ? input.launchAtStartup : DEFAULT_SETTINGS.launchAtStartup,
    scheduledScanEnabled: typeof input.scheduledScanEnabled === 'boolean' ? input.scheduledScanEnabled : DEFAULT_SETTINGS.scheduledScanEnabled,
    scheduledScanMode: ['quick', 'full'].includes(input.scheduledScanMode) ? input.scheduledScanMode : DEFAULT_SETTINGS.scheduledScanMode,
    scheduledScanHour: Number.isSafeInteger(input.scheduledScanHour) && input.scheduledScanHour >= 0 && input.scheduledScanHour <= 23 ? input.scheduledScanHour : DEFAULT_SETTINGS.scheduledScanHour,
    skipScheduledScanOnBattery: typeof input.skipScheduledScanOnBattery === 'boolean' ? input.skipScheduledScanOnBattery : DEFAULT_SETTINGS.skipScheduledScanOnBattery,
    ransomwareAuditEnabled: typeof input.ransomwareAuditEnabled === 'boolean' ? input.ransomwareAuditEnabled : DEFAULT_SETTINGS.ransomwareAuditEnabled,
    networkProtectionMode: ['audit', 'block'].includes(input.networkProtectionMode) ? input.networkProtectionMode : DEFAULT_SETTINGS.networkProtectionMode,
    reputationSharingEnabled: typeof input.reputationSharingEnabled === 'boolean' ? input.reputationSharingEnabled : DEFAULT_SETTINGS.reputationSharingEnabled
  };
}

function sanitizeState(input = {}) {
  return {
    lastScanAt: typeof input.lastScanAt === 'string' ? input.lastScanAt : null,
    lastSummary: input.lastSummary && typeof input.lastSummary === 'object' ? input.lastSummary : null,
    activity: Array.isArray(input.activity) ? input.activity.slice(0, 100) : [],
    latestReport: sanitizeLatestReport(input.latestReport),
    latestNetworkReport: sanitizeNetworkReport(input.latestNetworkReport),
    latestEdrReport: sanitizeEdrReport(input.latestEdrReport),
    latestExposureReport: sanitizeExposureReport(input.latestExposureReport),
    latestIntegrityReport: sanitizeIntegrityReport(input.latestIntegrityReport),
    latestThreatIntel: sanitizeThreatIntelResult(input.latestThreatIntel),
    activeOperation: sanitizeActiveOperation(input.activeOperation),
    ransomwareAlerts: Array.isArray(input.ransomwareAlerts) ? input.ransomwareAlerts.slice(0, 100).map(sanitizeRansomwareAlert).filter(Boolean) : [],
    networkProtection: sanitizeNetworkProtection(input.networkProtection)
  };
}

function sanitizeActiveOperation(value) {
  if (!value || typeof value !== 'object' || value.kind !== 'scan') return null;
  return {
    kind: 'scan', scanId: typeof value.scanId === 'string' ? value.scanId : '',
    mode: ['quick', 'deep', 'full', 'simulation'].includes(value.mode) ? value.mode : 'deep',
    startedAt: typeof value.startedAt === 'string' ? value.startedAt : null
  };
}

function sanitizeRansomwareAlert(value) {
  if (!value || typeof value !== 'object' || typeof value.id !== 'string') return null;
  return {
    id: value.id, at: typeof value.at === 'string' ? value.at : new Date(0).toISOString(),
    kind: String(value.kind ?? '').slice(0, 80), severity: ['medium', 'high', 'critical'].includes(value.severity) ? value.severity : 'medium',
    mode: 'audit', rootLabel: String(value.rootLabel ?? '').slice(0, 260), fileName: String(value.fileName ?? '').slice(0, 260),
    counts: { changed: safeNonNegative(value.counts?.changed), deleted: safeNonNegative(value.counts?.deleted), extensionChanges: safeNonNegative(value.counts?.extensionChanges) },
    process: { attributed: false, reason: 'Native process-write telemetry is not available in this build' },
    action: 'observed-only', explanation: String(value.explanation ?? '').slice(0, 500)
  };
}

function sanitizeNetworkReport(value) {
  const files = sanitizeLatestReport(value);
  if (!files) return null;
  return {
    ...files,
    summary: value.summary && typeof value.summary === 'object' ? value.summary : {},
    windowsSecurity: value.windowsSecurity && typeof value.windowsSecurity === 'object' ? value.windowsSecurity : {},
    events: Array.isArray(value.events) ? value.events.slice(0, 500) : []
  };
}

function sanitizeNetworkProtection(value) {
  const input = value && typeof value === 'object' ? value : {};
  return { mode: ['audit', 'block'].includes(input.mode) ? input.mode : 'audit', active: input.active === true, addressesBlocked: safeNonNegative(input.addressesBlocked), domainsPending: safeNonNegative(input.domainsPending), skippedDomains: Array.isArray(input.skippedDomains) ? input.skippedDomains.slice(0, 256).map(value => String(value).slice(0, 253)) : [], rules: Array.isArray(input.rules) ? input.rules.slice(0, 256).map(value => String(value).slice(0, 240)) : [], lastChangedAt: typeof input.lastChangedAt === 'string' ? input.lastChangedAt : null, error: input.error ? String(input.error).slice(0, 500) : null, blocking: false, reversible: true, group: 'Aegis Guard 0.7.0 Indicators' };
}

function sanitizeThreatIntelResult(value) {
  if (!value || typeof value !== 'object' || !/^[a-f0-9]{64}$/i.test(String(value.sha256 ?? ''))) return null;
  const sources = Array.isArray(value.sources) ? value.sources.slice(0, 8).map(source => ({
    provider: String(source?.provider ?? '').slice(0, 40),
    status: String(source?.status ?? '').slice(0, 40),
    kind: String(source?.kind ?? '').slice(0, 60),
    confidence: safeBoundedNumber(source?.confidence, 0, 100),
    trust: safeBoundedNumber(source?.trust, 0, 100),
    signature: String(source?.signature ?? '').slice(0, 240),
    source: String(source?.source ?? '').slice(0, 120),
    fileName: String(source?.fileName ?? '').slice(0, 240),
    fileSize: safeNonNegative(source?.fileSize),
    firstSeen: typeof source?.firstSeen === 'string' ? source.firstSeen.slice(0, 40) : null,
    families: Array.isArray(source?.families) ? source.families.slice(0, 16).map(item => String(item).slice(0, 160)) : [],
    tags: Array.isArray(source?.tags) ? source.tags.slice(0, 16).map(item => String(item).slice(0, 80)) : [],
    matches: safeNonNegative(source?.matches),
    error: source?.error ? String(source.error).slice(0, 240) : null
  })).filter(source => source.provider && source.status) : [];
  return {
    schemaVersion: 1,
    sha256: String(value.sha256).toLowerCase(),
    verdict: ['known-malicious', 'known-file-context', 'unknown', 'unavailable'].includes(value.verdict) ? value.verdict : 'unknown',
    confidence: safeBoundedNumber(value.confidence, 0, 100),
    queriedAt: typeof value.queriedAt === 'string' ? value.queriedAt.slice(0, 40) : null,
    expiresAt: typeof value.expiresAt === 'string' ? value.expiresAt.slice(0, 40) : null,
    sources
  };
}

function sanitizeExposureReport(value) {
  if (!value || typeof value !== 'object') return null;
  const jsonFile = typeof value.jsonFile === 'string' && path.basename(value.jsonFile) === value.jsonFile ? value.jsonFile : null;
  const csvFile = typeof value.csvFile === 'string' && path.basename(value.csvFile) === value.csvFile ? value.csvFile : null;
  const summary = value.summary && typeof value.summary === 'object' ? {
    removableDevices: safeNonNegative(value.summary.removableDevices), applications: safeNonNegative(value.summary.applications),
    applicationsWithoutVersion: safeNonNegative(value.summary.applicationsWithoutVersion), applicationsWithoutPublisher: safeNonNegative(value.summary.applicationsWithoutPublisher),
    unsafeSettings: safeNonNegative(value.summary.unsafeSettings), privacyEntries: safeNonNegative(value.summary.privacyEntries),
    policyIndicators: safeNonNegative(value.summary.policyIndicators), expiredExceptions: safeNonNegative(value.summary.expiredExceptions), truncated: Boolean(value.summary.truncated)
  } : { removableDevices: 0, applications: 0, applicationsWithoutVersion: 0, applicationsWithoutPublisher: 0, unsafeSettings: 0, privacyEntries: 0, policyIndicators: 0, expiredExceptions: 0, truncated: false };
  return {
    schemaVersion: 1, mode: 'audit', available: Boolean(value.available), source: value.source === 'windows-powershell' ? value.source : 'unavailable',
    startedAt: typeof value.startedAt === 'string' ? value.startedAt : null, completedAt: typeof value.completedAt === 'string' ? value.completedAt : null,
    reportAvailable: Boolean(value.reportAvailable || (jsonFile && csvFile)), jsonFile, csvFile,
    limitations: Array.isArray(value.limitations) ? value.limitations.slice(0, 8).map(item => String(item).slice(0, 500)) : [], summary,
    devices: Array.isArray(value.devices) ? value.devices.slice(0, 64).map(item => ({ id: String(item?.id ?? '').slice(0, 80), drive: String(item?.drive ?? '').slice(0, 8), label: String(item?.label ?? '').slice(0, 260), fileSystem: String(item?.fileSystem ?? '').slice(0, 80), sizeBytes: safeNonNegative(item?.sizeBytes), freeBytes: safeNonNegative(item?.freeBytes), provider: String(item?.provider ?? '').slice(0, 260), status: 'observed', control: 'audit-only' })) : [],
    applications: Array.isArray(value.applications) ? value.applications.slice(0, 1_000).map(item => ({ name: String(item?.name ?? '').slice(0, 260), publisher: String(item?.publisher ?? '').slice(0, 260), version: String(item?.version ?? '').slice(0, 120), installDate: typeof item?.installDate === 'string' ? item.installDate : null, installLocation: String(item?.installLocation ?? '').slice(0, 1_000), uninstallString: String(item?.uninstallString ?? '').slice(0, 2_000), estimatedSizeKb: safeNonNegative(item?.estimatedSizeKb), policy: { status: ['expired-exception', 'exception', 'publisher-allowed', 'unmatched'].includes(item?.policy?.status) ? item.policy.status : 'unmatched', severity: ['info', 'low', 'medium'].includes(item?.policy?.severity) ? item.policy.severity : 'info', hash: null, enforcement: 'audit-only', explanation: String(item?.policy?.explanation ?? '').slice(0, 500) } })) : [],
    unsafeSettings: Array.isArray(value.unsafeSettings) ? value.unsafeSettings.slice(0, 64).map(item => ({ id: String(item?.id ?? '').slice(0, 80), title: String(item?.title ?? '').slice(0, 260), severity: ['low', 'medium', 'high'].includes(item?.severity) ? item.severity : 'low', explanation: String(item?.explanation ?? '').slice(0, 500) })) : [],
    privacy: Array.isArray(value.privacy) ? value.privacy.slice(0, 256).map(item => ({ capability: item?.capability === 'microphone' ? 'microphone' : 'webcam', app: String(item?.app ?? '(global)').slice(0, 260), decision: ['allowed', 'denied', 'unknown'].includes(item?.decision) ? item.decision : 'unknown', lastUsed: typeof item?.lastUsed === 'string' ? item.lastUsed : null, severity: ['low', 'medium', 'high'].includes(item?.severity) ? item.severity : 'info', explanation: String(item?.explanation ?? '').slice(0, 500) })) : [],
    security: { firewall: Array.isArray(value.security?.firewall) ? value.security.firewall.slice(0, 8).map(item => ({ name: String(item?.name ?? '').slice(0, 40), enabled: Boolean(item?.enabled), defaultInboundAction: String(item?.defaultInboundAction ?? '').slice(0, 40), defaultOutboundAction: String(item?.defaultOutboundAction ?? '').slice(0, 40) })) : [], defender: value.security?.defender && typeof value.security.defender === 'object' ? { antivirusEnabled: Boolean(value.security.defender.antivirusEnabled), realTimeProtectionEnabled: Boolean(value.security.defender.realTimeProtectionEnabled), behaviorMonitorEnabled: Boolean(value.security.defender.behaviorMonitorEnabled), networkInspectionEnabled: Boolean(value.security.defender.networkInspectionEnabled) } : null, uac: value.security?.uac && typeof value.security.uac === 'object' ? { enableLUA: Boolean(value.security.uac.enableLUA), consentPromptBehaviorAdmin: safeNonNegative(value.security.uac.consentPromptBehaviorAdmin), promptOnSecureDesktop: Boolean(value.security.uac.promptOnSecureDesktop) } : null, secureBoot: Boolean(value.security?.secureBoot) },
    policies: { mode: 'audit', publishers: Array.isArray(value.policies?.publishers) ? value.policies.publishers.slice(0, 256).map(item => String(item).slice(0, 260)) : [], hashes: Array.isArray(value.policies?.hashes) ? value.policies.hashes.slice(0, 256).map(item => String(item).slice(0, 128)) : [], exceptions: Array.isArray(value.policies?.exceptions) ? value.policies.exceptions.slice(0, 256).map(item => ({ name: String(item?.name ?? '').slice(0, 260), expiresAt: typeof item?.expiresAt === 'string' ? item.expiresAt : null, reason: String(item?.reason ?? '').slice(0, 500) })) : [], expiredExceptions: Array.isArray(value.policies?.expiredExceptions) ? value.policies.expiredExceptions.slice(0, 256).map(item => ({ name: String(item?.name ?? '').slice(0, 260), expiresAt: typeof item?.expiresAt === 'string' ? item.expiresAt : null, reason: String(item?.reason ?? '').slice(0, 500) })) : [], enforcementAvailable: false, blocking: false }
  };
}

function sanitizeIntegrityReport(value) {
  if (!value || typeof value !== 'object') return null;
  const fileName = name => typeof name === 'string' && path.basename(name) === name ? name : null;
  const summaryInput = value.summary && typeof value.summary === 'object' ? value.summary : {};
  const items = Array.isArray(value.items) ? value.items.slice(0, 256).map(item => ({
    path: String(item?.path ?? '').slice(0, 1_000),
    status: ['verified', 'modified', 'missing', 'untracked'].includes(item?.status) ? item.status : 'missing',
    expectedSha256: typeof item?.expectedSha256 === 'string' && /^[a-f0-9]{64}$/i.test(item.expectedSha256) ? item.expectedSha256.toLowerCase() : null,
    actualSha256: typeof item?.actualSha256 === 'string' && /^[a-f0-9]{64}$/i.test(item.actualSha256) ? item.actualSha256.toLowerCase() : null,
    sizeBytes: safeNonNegative(item?.sizeBytes),
    error: item?.error ? String(item.error).slice(0, 300) : null
  })) : [];
  return {
    schemaVersion: 1, mode: 'audit', available: Boolean(value.available), source: value.source === 'local-manifest' ? 'local-manifest' : 'unavailable',
    startedAt: typeof value.startedAt === 'string' ? value.startedAt : null, completedAt: typeof value.completedAt === 'string' ? value.completedAt : null,
    manifestVersion: String(value.manifestVersion ?? '').slice(0, 120), manifestGeneratedAt: typeof value.manifestGeneratedAt === 'string' ? value.manifestGeneratedAt : null,
    signature: { status: ['present-unverified', 'not-configured', 'verified'].includes(value.signature?.status) ? value.signature.status : 'not-configured', algorithm: value.signature?.algorithm ? String(value.signature.algorithm).slice(0, 80) : null },
    reportAvailable: Boolean(value.reportAvailable || (fileName(value.jsonFile) && fileName(value.csvFile))), jsonFile: fileName(value.jsonFile), csvFile: fileName(value.csvFile), error: value.error ? String(value.error).slice(0, 500) : undefined,
    limitations: Array.isArray(value.limitations) ? value.limitations.slice(0, 8).map(item => String(item).slice(0, 500)) : [],
    summary: { total: safeNonNegative(summaryInput.total), verified: safeNonNegative(summaryInput.verified), modified: safeNonNegative(summaryInput.modified), missing: safeNonNegative(summaryInput.missing), untracked: safeNonNegative(summaryInput.untracked), healthy: Boolean(summaryInput.healthy), truncated: Boolean(summaryInput.truncated) },
    items,
    enforcement: { mode: 'audit', blocking: false, repairAvailable: false, serviceProtected: false }
  };
}

function sanitizeEdrReport(value) {
  if (!value || typeof value !== 'object') return null;
  const processValues = Array.isArray(value.processes) ? value.processes.slice(0, 512).map(item => ({
    pid: safeNonNegative(item?.pid), parentPid: safeNonNegative(item?.parentPid), name: String(item?.name ?? '').slice(0, 260),
    path: String(item?.path ?? '').slice(0, 1_000), commandLine: String(item?.commandLine ?? '').slice(0, 2_000),
    createdAt: typeof item?.createdAt === 'string' ? item.createdAt : null,
    children: Array.isArray(item?.children) ? item.children.slice(0, 32).map(safeNonNegative) : []
  })) : [];
  const artifacts = Array.isArray(value.persistenceArtifacts) ? value.persistenceArtifacts.slice(0, 1_024).map(item => ({
    type: String(item?.type ?? 'persistence').slice(0, 80), name: String(item?.name ?? '').slice(0, 260), path: String(item?.path ?? '').slice(0, 1_000),
    command: String(item?.command ?? '').slice(0, 2_000), userWritable: Boolean(item?.userWritable), verdict: item?.verdict === 'suspicious' ? 'suspicious' : 'observed',
    techniqueIds: Array.isArray(item?.techniqueIds) ? item.techniqueIds.slice(0, 8).map(value => String(value).slice(0, 40)) : [],
    techniqueLabels: Array.isArray(item?.techniqueLabels) ? item.techniqueLabels.slice(0, 8).map(value => String(value).slice(0, 180)) : [],
    explanation: String(item?.explanation ?? '').slice(0, 500)
  })) : [];
  const events = Array.isArray(value.events) ? value.events.slice(0, 300).map(item => ({
    id: typeof item?.id === 'string' ? item.id : crypto.randomUUID(), at: typeof item?.at === 'string' ? item.at : new Date(0).toISOString(),
    kind: ['process', 'persistence', 'network', 'file', 'ransomware'].includes(item?.kind) ? item.kind : 'process',
    severity: ['info', 'low', 'medium', 'high', 'critical'].includes(item?.severity) ? item.severity : 'info',
    verdict: item?.verdict === 'suspicious' ? 'suspicious' : 'observed', title: String(item?.title ?? 'Evento EDR').slice(0, 260),
    explanation: String(item?.explanation ?? '').slice(0, 500), source: 'local-audit',
    techniqueIds: Array.isArray(item?.techniqueIds) ? item.techniqueIds.slice(0, 8).map(value => String(value).slice(0, 40)) : [],
    techniqueLabels: Array.isArray(item?.techniqueLabels) ? item.techniqueLabels.slice(0, 8).map(value => String(value).slice(0, 180)) : [],
    process: sanitizeEdrProcess(item?.process), artifact: item?.artifact && typeof item.artifact === 'object' ? { type: String(item.artifact.type ?? 'artifact').slice(0, 80), path: String(item.artifact.path ?? '').slice(0, 1_000), label: String(item.artifact.label ?? '').slice(0, 260) } : null,
    action: 'observed-only'
  })) : [];
  const incidents = Array.isArray(value.incidents) ? value.incidents.slice(0, 100).map(item => ({
    id: typeof item?.id === 'string' ? item.id : crypto.randomUUID(), at: typeof item?.at === 'string' ? item.at : null,
    severity: ['medium', 'high', 'critical'].includes(item?.severity) ? item.severity : 'medium', title: String(item?.title ?? 'Incidente observado').slice(0, 260), status: 'observed',
    eventCount: safeNonNegative(item?.eventCount), eventIds: Array.isArray(item?.eventIds) ? item.eventIds.slice(0, 50).map(value => String(value).slice(0, 80)) : [],
    techniqueIds: Array.isArray(item?.techniqueIds) ? item.techniqueIds.slice(0, 8).map(value => String(value).slice(0, 40)) : [],
    techniqueLabels: Array.isArray(item?.techniqueLabels) ? item.techniqueLabels.slice(0, 8).map(value => String(value).slice(0, 180)) : [],
    process: sanitizeEdrProcess(item?.process), response: sanitizeEdrResponse(item?.response)
  })) : [];
  const jsonFile = typeof value.jsonFile === 'string' && path.basename(value.jsonFile) === value.jsonFile ? value.jsonFile : null;
  return {
    schemaVersion: 1, mode: 'audit', available: Boolean(value.available), source: value.source === 'windows-powershell' ? value.source : 'unavailable',
    startedAt: typeof value.startedAt === 'string' ? value.startedAt : null, completedAt: typeof value.completedAt === 'string' ? value.completedAt : null,
    reportAvailable: Boolean(value.reportAvailable || jsonFile), jsonFile,
    limitations: Array.isArray(value.limitations) ? value.limitations.slice(0, 8).map(item => String(item).slice(0, 500)) : [],
    summary: { processes: safeNonNegative(value.summary?.processes), processTreeEdges: safeNonNegative(value.summary?.processTreeEdges), persistenceArtifacts: safeNonNegative(value.summary?.persistenceArtifacts), timelineEvents: safeNonNegative(value.summary?.timelineEvents), incidents: safeNonNegative(value.summary?.incidents), suspicious: safeNonNegative(value.summary?.suspicious), truncated: Boolean(value.summary?.truncated) },
    processes: processValues, processTreeEdges: Array.isArray(value.processTreeEdges) ? value.processTreeEdges.slice(0, 512).map(edge => ({ parentPid: safeNonNegative(edge?.parentPid), childPid: safeNonNegative(edge?.childPid) })) : [], persistenceArtifacts: artifacts, events, incidents,
    response: sanitizeEdrResponse(value.response), error: value.error ? String(value.error).slice(0, 500) : undefined
  };
}

function sanitizeEdrProcess(value) {
  const input = value && typeof value === 'object' ? value : {};
  return { attributed: Boolean(input.attributed), pid: safeNonNegative(input.pid), name: String(input.name ?? '').slice(0, 260), path: String(input.path ?? '').slice(0, 1_000), parentPid: safeNonNegative(input.parentPid), reason: String(input.reason ?? '').slice(0, 260) };
}

function sanitizeEdrResponse(value) {
  return { mode: 'audit', blocking: false, terminationAvailable: false, removalAvailable: false, quarantineAvailable: false };
}

function sanitizeLatestReport(value) {
  if (!value || typeof value !== 'object') return null;
  const jsonFile = typeof value.jsonFile === 'string' && path.basename(value.jsonFile) === value.jsonFile ? value.jsonFile : null;
  const csvFile = typeof value.csvFile === 'string' && path.basename(value.csvFile) === value.csvFile ? value.csvFile : null;
  if (!jsonFile || !csvFile) return null;
  return {
    scanId: typeof value.scanId === 'string' ? value.scanId : '',
    completedAt: typeof value.completedAt === 'string' ? value.completedAt : null,
    count: Number.isSafeInteger(value.count) && value.count >= 0 ? value.count : 0,
    jsonFile, csvFile
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

function normalizeProtectedDirectories(value) {
  if (!Array.isArray(value)) throw new Error('Protected directories must be an array');
  const output = [];
  const seen = new Set();
  for (const item of value.slice(0, 8)) {
    if (typeof item !== 'string' || !path.isAbsolute(item)) continue;
    const resolved = path.resolve(item);
    const key = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
    if (!seen.has(key)) { seen.add(key); output.push(resolved); }
  }
  return output;
}

function safeNonNegative(value) {
  return Number.isSafeInteger(value) && value >= 0 ? Math.min(value, 1_000_000) : 0;
}

function safeBoundedNumber(value, minimum, maximum) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(minimum, Math.min(maximum, number)) : null;
}

function performanceDelta(before, after) {
  const cacheHits = Math.max(0, after.cacheHits - before.cacheHits);
  const cacheMisses = Math.max(0, after.cacheMisses - before.cacheMisses);
  return {
    cacheHits,
    cacheMisses,
    cacheHitRate: cacheHits + cacheMisses ? Math.round(cacheHits * 10_000 / (cacheHits + cacheMisses)) / 100 : 0,
    bytesRead: Math.max(0, after.bytesRead - before.bytesRead),
    peakWorkingBufferBytes: after.peakWorkingBufferBytes
  };
}

function resolveScanConcurrency(configured) {
  const requested = Number.isSafeInteger(configured) ? configured : Number(configured) || 1;
  const logicalCpus = typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, Math.min(requested, logicalCpus <= 2 ? 1 : 2));
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

function operationError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
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
