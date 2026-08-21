import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppService } from '../src/app-service.mjs';
import { discoverWindowsDriveRoots, parseWindowsDriveRoots, resolveSystemPowerShell } from '../src/drive-roots.mjs';
import { createHarmlessSimulation } from '../src/simulator.mjs';
import { WatchService, isTemporaryDownload } from '../src/watch-service.mjs';

const baseDirectory = fileURLToPath(new URL('..', import.meta.url));

test('Windows drive discovery accepts only canonical drive-letter roots', () => {
  assert.deepEqual(
    parseWindowsDriveRoots('Fixed|c:\\\r\nRemovable|D:\\\r\nFixed|C:\\\r\n\\\\server\\share\r\ninvalid\r\n'),
    ['C:\\', 'D:\\']
  );
});

test('PowerShell drive enumeration uses a validated absolute SystemRoot path and fails closed', async t => {
  assert.equal(
    resolveSystemPowerShell({ SystemRoot: 'C:\\Windows' }),
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
  );
  assert.throws(() => resolveSystemPowerShell({ SystemRoot: 'relative\\Windows' }), /SystemRoot/);
  if (process.platform !== 'win32') {
    t.skip('PowerShell execution path is Windows-only');
    return;
  }
  await assert.rejects(
    discoverWindowsDriveRoots({
      environment: { SystemRoot: process.env.SystemRoot },
      execFileImpl: async () => { throw new Error('Injected enumeration failure'); }
    }),
    error => error?.code === 'DRIVE_ENUMERATION_FAILED'
  );
});

async function createFixture(t, { driveRootsProvider } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-desktop-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  const services = [];
  await fs.mkdir(downloadsDirectory, { recursive: true });

  t.after(async () => {
    await Promise.allSettled(services.map(service => service.shutdown()));
    await fs.rm(root, { recursive: true, force: true });
  });

  return {
    root,
    dataDirectory,
    downloadsDirectory,
    createService(options = {}) {
      const service = new AppService({
        baseDirectory,
        dataDirectory,
        downloadsDirectory,
        driveRootsProvider,
        ...options
      });
      services.push(service);
      return service;
    }
  };
}

test('Downloads protection starts active and excludes incomplete browser downloads', async t => {
  const fixture = await createFixture(t);
  const events = [];
  const service = fixture.createService({ emit: event => events.push(event) });
  const bootstrap = await service.init();

  assert.deepEqual(bootstrap.protection, {
    active: true,
    paused: false,
    targetLabel: 'Descargas',
    autoQuarantine: false,
    sessionOnly: true,
    error: null
  });
  assert.equal(isTemporaryDownload(path.join(fixture.downloadsDirectory, 'video.crdownload')), true);
  assert.equal(isTemporaryDownload(path.join(fixture.downloadsDirectory, 'archive.PART')), true);
  assert.equal(isTemporaryDownload(path.join(fixture.downloadsDirectory, 'stable.partial')), false);
  assert.equal(isTemporaryDownload(path.join(fixture.downloadsDirectory, 'stable.download')), false);
  assert.equal(isTemporaryDownload(path.join(fixture.downloadsDirectory, 'stable.tmp')), false);
  assert.equal(isTemporaryDownload(path.join(fixture.downloadsDirectory, 'finished.zip')), false);
  assert.equal(
    service.downloadsWatchService.isExcluded(
      path.join(fixture.downloadsDirectory, 'video.crdownload'),
      fixture.downloadsDirectory
    ),
    true
  );
  assert.equal(
    service.downloadsWatchService.isExcluded(
      path.join(fixture.downloadsDirectory, 'archive.part'),
      fixture.downloadsDirectory
    ),
    true
  );
  assert.equal(events.some(event => event.type === 'protection-detection'), false);
});

test('real-time inspection scans stable temporary names and excluded-name folders after browser rename', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-watch-inclusive-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const nested = path.join(root, '.git');
  await fs.mkdir(nested);
  const nestedFile = path.join(nested, 'nested.exe');
  const stableTmp = path.join(root, 'stable.tmp');
  const partial = path.join(root, 'browser.crdownload');
  await Promise.all([
    fs.writeFile(nestedFile, 'nested fixture'),
    fs.writeFile(stableTmp, 'stable tmp fixture'),
    fs.writeFile(partial, 'browser fixture')
  ]);

  const scanned = [];
  const watcher = new WatchService({
    engine: {
      isExcludedPath: () => false,
      async scanFile() {
        throw new Error('Real-time protection must not use the Quick size-limited reader');
      },
      async scanFileExhaustive(file) {
        scanned.push(file);
        return { path: file, verdict: 'clean', score: 0, findings: [] };
      }
    },
    quarantine: { isTransientPath: () => false },
    stabilityRequired: 1
  });
  const session = { root: await fs.realpath(root), controller: new AbortController(), autoQuarantine: false };
  assert.equal(watcher.isExcluded(nestedFile, root), false);
  assert.equal(watcher.isExcluded(stableTmp, root), false);
  assert.equal(watcher.isExcluded(partial, root), true);
  await watcher.inspect(nestedFile, session);
  await watcher.inspect(stableTmp, session);

  const completed = path.join(root, 'browser.exe');
  await fs.rename(partial, completed);
  assert.equal(watcher.isExcluded(completed, root), false);
  await watcher.inspect(completed, session);
  assert.deepEqual(scanned.map(file => path.basename(file)).sort(), ['browser.exe', 'nested.exe', 'stable.tmp']);
});

test('protection pause is session-only and is reset by a new AppService init', async t => {
  const fixture = await createFixture(t);
  const first = fixture.createService();
  const initial = await first.init();
  assert.equal(initial.protection.active, true);
  assert.equal(initial.protection.paused, false);

  const paused = await first.pauseProtection();
  assert.equal(paused.active, false);
  assert.equal(paused.paused, true);
  assert.equal(first.getProtectionState().paused, true);

  await first.shutdown();
  const second = fixture.createService();
  const restarted = await second.init();
  assert.equal(restarted.protection.active, true);
  assert.equal(restarted.protection.paused, false);
  assert.equal(restarted.protection.sessionOnly, true);
});

test('pause restores a pending manual monitor unless it is stopped while paused', async t => {
  const fixture = await createFixture(t);
  const monitoredDirectory = path.join(fixture.root, 'manual-monitor');
  await fs.mkdir(monitoredDirectory);
  const service = fixture.createService();
  await service.init();

  const started = await service.startMonitor(monitoredDirectory, { autoQuarantine: false });
  const canonicalMonitor = await fs.realpath(monitoredDirectory);
  assert.equal(started.active, true);
  assert.equal(service.watchService.session.root, canonicalMonitor);

  await service.pauseProtection();
  assert.equal(service.watchService.session, null);
  assert.equal(service.manualMonitorConfig.target, path.resolve(monitoredDirectory));

  await service.resumeProtection();
  assert.equal(service.watchService.session.root, canonicalMonitor);

  await service.pauseProtection();
  const stopped = await service.stopMonitor();
  assert.equal(stopped.pending, false);
  assert.equal(service.manualMonitorConfig, null);
  await service.resumeProtection();
  assert.equal(service.watchService.session, null);
});

test('launchAtStartup is boolean-sanitized and persists across AppService sessions', async t => {
  const fixture = await createFixture(t);
  const first = fixture.createService();
  const initial = await first.init();
  assert.equal(initial.settings.launchAtStartup, true);

  assert.equal((await first.saveSettings({ launchAtStartup: false })).launchAtStartup, false);
  const storedDisabled = JSON.parse(await fs.readFile(path.join(fixture.dataDirectory, 'settings.json'), 'utf8'));
  assert.equal(storedDisabled.launchAtStartup, false);
  assert.equal(typeof storedDisabled.launchAtStartup, 'boolean');

  await first.shutdown();
  const second = fixture.createService();
  const restartedDisabled = await second.init();
  assert.equal(restartedDisabled.settings.launchAtStartup, false);

  assert.equal((await second.saveSettings({ launchAtStartup: true })).launchAtStartup, true);
  await second.shutdown();
  const third = fixture.createService();
  const restartedEnabled = await third.init();
  assert.equal(restartedEnabled.settings.launchAtStartup, true);
});

test('full scan aggregates only injected temporary roots and traversal failures', async t => {
  let providerCalls = 0;
  let driveRoots = [];
  const fixture = await createFixture(t, {
    driveRootsProvider: async () => {
      providerCalls++;
      return driveRoots;
    }
  });
  const firstRoot = path.join(fixture.root, 'drive-a');
  const secondRoot = path.join(fixture.root, 'drive-b');
  const disappearedRoot = path.join(fixture.root, 'removed-drive');
  await Promise.all([
    fs.mkdir(firstRoot),
    fs.mkdir(secondRoot)
  ]);
  await Promise.all([
    fs.writeFile(path.join(firstRoot, 'one.txt'), 'ordinary fixture one'),
    fs.writeFile(path.join(firstRoot, 'two.txt'), 'ordinary fixture two')
  ]);
  const simulation = await createHarmlessSimulation(secondRoot);
  const excludedDataDirectory = path.join(firstRoot, 'aegis-private-data');
  const excludedSimulation = await createHarmlessSimulation(path.join(excludedDataDirectory, 'quarantine'));
  driveRoots = [firstRoot, secondRoot, disappearedRoot];

  const events = [];
  const service = fixture.createService({
    dataDirectory: excludedDataDirectory,
    emit: event => events.push(event)
  });
  await service.init();
  const report = await service.startScan({ mode: 'full', autoQuarantine: false });

  assert.equal(providerCalls, 1);
  assert.equal(report.mode, 'full');
  assert.equal(report.path, null);
  assert.equal(report.summary.rootsScanned, driveRoots.length);
  assert.equal(report.summary.scanned, 3);
  assert.equal(report.summary.malicious, 1);
  assert.equal(report.summary.suspicious, 0);
  assert.equal(report.summary.errors, 0);
  assert.equal(report.summary.traversalErrors, 1);
  assert.equal(report.summary.quarantined, 0);
  assert.equal(report.results.length, 2);
  assert.ok(report.results.some(result => result.path === simulation && result.verdict === 'malicious'));
  assert.ok(report.results.some(result => result.verdict === 'error' && result.detailType === 'traversal-error'));
  assert.equal(report.results.some(result => result.path === excludedSimulation), false);
  assert.ok(events.some(event => event.type === 'scan-traversal-error'));
  assert.ok(events.some(event =>
    event.type === 'scan-completed' && event.payload.summary.scanned === 3
  ));
  assert.ok(events.some(event =>
    event.type === 'scan-progress'
      && event.payload.rootsCompleted === driveRoots.length
      && event.payload.rootsTotal === driveRoots.length
  ));
});
