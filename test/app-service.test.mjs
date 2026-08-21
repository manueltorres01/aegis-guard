import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppService } from '../src/app-service.mjs';
import { createHarmlessSimulation } from '../src/simulator.mjs';
import crypto from 'node:crypto';

const baseDirectory = fileURLToPath(new URL('..', import.meta.url));

test('AppService defaults to manual quarantine and keeps desktop data under dataDirectory', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-service-'));
  const dataDirectory = path.join(root, 'app-data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const events = [];
  const service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    emit: event => events.push(event)
  });
  t.after(async () => {
    await service.shutdown();
    await fs.rm(root, { recursive: true, force: true });
  });

  const bootstrap = await service.init();
  assert.equal(bootstrap.settings.autoQuarantine, false);
  assert.equal(service.settings.autoQuarantine, false);
  assert.equal(service.quarantine.directory, path.join(dataDirectory, 'quarantine'));
  assert.equal((await fs.stat(path.join(dataDirectory, 'quarantine'))).isDirectory(), true);
  assert.equal((await fs.stat(path.join(dataDirectory, 'quarantine', '.key'))).isFile(), true);

  const manualSample = await createHarmlessSimulation(downloadsDirectory);
  const manualReport = await service.startScan({ target: manualSample });
  assert.equal(manualReport.summary.malicious, 1);
  assert.equal(manualReport.summary.quarantined, 0);
  assert.equal((await fs.stat(manualSample)).isFile(), true);
  assert.equal((await service.listQuarantine()).items.length, 0);

  const simulationReport = await service.createAndScanSimulation();
  assert.equal(simulationReport.cancelled, undefined);
  assert.equal(simulationReport.summary.scanned, 1);
  assert.equal(simulationReport.summary.malicious, 1);
  assert.equal(simulationReport.summary.quarantined, 1);
  assert.equal(simulationReport.results[0].action, 'quarantined');
  await assert.rejects(fs.access(simulationReport.results[0].path), { code: 'ENOENT' });

  const quarantined = await service.listQuarantine();
  assert.equal(quarantined.items.length, 1);
  assert.equal(quarantined.total, 1);
  assert.ok(path.resolve(quarantined.items[0].originalPath).startsWith(`${path.resolve(dataDirectory)}${path.sep}`));
  assert.equal((await fs.stat(path.join(dataDirectory, 'quarantine', `${quarantined.items[0].id}.bin`))).isFile(), true);
  assert.equal((await fs.stat(path.join(dataDirectory, 'quarantine', `${quarantined.items[0].id}.json`))).isFile(), true);
  const populatedBootstrap = await service.getBootstrap();
  const latestJson = await service.getLatestReport('json');
  const latestCsv = await service.getLatestReport('csv');
  assert.equal(JSON.parse(await fs.readFile(latestJson.path, 'utf8')).results.length, 1);
  assert.match(await fs.readFile(latestCsv.path, 'utf8'), /"path","verdict"/);
  assert.equal(populatedBootstrap.reportAvailable, true);
  assert.equal(populatedBootstrap.quarantineCount, 1);
  assert.equal(populatedBootstrap.quarantine.length, 1);
  assert.equal(populatedBootstrap.quarantineInventory.total, 1);
  assert.equal(populatedBootstrap.quarantineInventory.truncatedCount, 0);
  assert.equal(populatedBootstrap.quarantineInventory.corruptCount, 0);
  assert.equal(populatedBootstrap.quarantineInventory.oversizedCount, 0);
  assert.ok(events.some(event => event.type === 'scan-started' && event.payload.autoQuarantine === false));
  assert.ok(events.some(event => event.type === 'quarantine-changed' && event.payload.action === 'isolated'));
});

test('completed restore and real-time detections survive state persistence failure', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-state-warning-'));
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory);
  const events = [];
  const service = new AppService({
    baseDirectory,
    dataDirectory: path.join(root, 'data'),
    downloadsDirectory,
    emit: event => events.push(event)
  });
  await service.init();
  t.after(async () => {
    await service.shutdown();
    await fs.rm(root, { recursive: true, force: true });
  });

  const sample = await createHarmlessSimulation(downloadsDirectory);
  const report = await service.startScan({ mode: 'deep', target: sample, autoQuarantine: true });
  const item = (await service.listQuarantine()).items[0];
  const destination = path.join(root, 'restored.txt');
  service.persistState = async () => { throw new Error('Injected persistence failure'); };

  assert.equal(await service.restoreQuarantine(item.id, destination), path.resolve(destination));
  assert.equal((await fs.stat(destination)).isFile(), true);
  service.handleProtectionEvent({
    type: 'monitor-result',
    payload: { result: { path: destination, verdict: 'suspicious', score: 40, findings: [] } }
  });
  await service.flushScheduledPersistence();
  assert.ok(events.filter(event => event.type === 'scan-warning' && event.payload.code === 'STATE_NOT_PERSISTED').length >= 2);
  assert.equal(report.summary.quarantined, 1);
});

test('startup recovers an interrupted scan journal and reports degraded health', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-recovery-'));
  t.after(() => fs.rm(root, { recursive:true, force:true }));
  const dataDirectory = path.join(root, 'data'); const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(dataDirectory, {recursive:true}); await fs.mkdir(downloadsDirectory, {recursive:true});
  await fs.writeFile(path.join(dataDirectory,'state.json'), JSON.stringify({activeOperation:{kind:'scan',scanId:'76d2809c-2614-45df-908f-587506ab3949',mode:'full',startedAt:'2026-08-20T01:00:00.000Z'},activity:[]}));
  const service = new AppService({baseDirectory:path.resolve('.'),dataDirectory,downloadsDirectory});
  t.after(() => service.shutdown());
  const bootstrap = await service.init();
  assert.equal(bootstrap.health.status,'degraded');
  assert.equal(bootstrap.health.recoveredInterruptedOperation,true);
  assert.equal(bootstrap.activity[0].type,'recovery');
  const stored=JSON.parse(await fs.readFile(path.join(dataDirectory,'state.json'),'utf8'));
  assert.equal(stored.activeOperation,null);
});

test('ransomware audit is opt-in, pauses with protection and removes only owned canaries when disabled', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-ransomware-service-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  const documentsDirectory = path.join(root, 'documents');
  await Promise.all([downloadsDirectory, documentsDirectory].map(directory => fs.mkdir(directory, { recursive: true })));
  const service = new AppService({ baseDirectory, dataDirectory, downloadsDirectory, protectedDirectories: [documentsDirectory] });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  let bootstrap = await service.init();
  assert.equal(bootstrap.ransomwareAudit.configured, false);
  assert.equal(bootstrap.ransomwareAudit.enabled, false);
  await service.saveSettings({ ransomwareAuditEnabled: true });
  bootstrap = await service.getBootstrap();
  assert.equal(bootstrap.ransomwareAudit.enabled, true);
  assert.equal(bootstrap.ransomwareAudit.rootsObserved, 1);
  const canary = (await fs.readdir(documentsDirectory)).find(name => name.startsWith('_AegisGuard_Canary_'));
  assert.ok(canary);
  await service.pauseProtection();
  assert.equal(service.getRansomwareAuditState().paused, true);
  await service.saveSettings({ ransomwareAuditEnabled: false });
  assert.equal(await fs.stat(path.join(documentsDirectory, canary)).then(() => true, () => false), false);
});

test('EDR audit persists a bounded report and exposes it in bootstrap', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-edr-service-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const service = new AppService({ baseDirectory, dataDirectory, downloadsDirectory });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  await service.init();
  service.edrAuditor.runner = async () => ({ Processes: [{ ProcessId: 1, ParentProcessId: 0, Name: 'powershell.exe', CommandLine: 'powershell.exe -enc AAA=' }] });
  const report = await service.runEdrAudit();
  assert.equal(report.reportAvailable, true);
  assert.equal(report.response.terminationAvailable, false);
  assert.ok(report.summary.suspicious >= 1);
  const bootstrap = await service.getBootstrap();
  assert.equal(bootstrap.edr.reportAvailable, true);
  const latest = await service.getLatestEdrReport();
  assert.equal(JSON.parse(await fs.readFile(latest.path, 'utf8')).schemaVersion, 1);
});

test('exposure audit persists a read-only inventory and supports latest report export', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-exposure-service-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    exposureOptions: {
      runner: async () => ({ Devices: [{ DeviceID: 'E:', VolumeName: 'USB' }], Applications: [{ DisplayName: 'Discord', Publisher: 'Discord Inc.' }], Privacy: [] })
    }
  });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  await service.init();
  const report = await service.runExposureAudit();
  assert.equal(report.reportAvailable, true);
  assert.equal(report.summary.removableDevices, 1);
  assert.equal(report.summary.applications, 1);
  const bootstrap = await service.getBootstrap();
  assert.equal(bootstrap.exposure.reportAvailable, true);
  const latest = await service.getLatestExposureReport('json');
  assert.equal(JSON.parse(await fs.readFile(latest.path, 'utf8')).schemaVersion, 1);
  const csv = await service.getLatestExposureReport('csv');
  assert.match(await fs.readFile(csv.path, 'utf8'), /application/);
});

test('integrity audit persists a bounded self-protection report', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-integrity-service-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const manifestPath = path.join(root, 'manifest.json');
  await fs.writeFile(path.join(root, 'protected.txt'), 'baseline');
  const { createIntegrityManifest } = await import('../src/self-protection-audit.mjs');
  await fs.writeFile(manifestPath, JSON.stringify(await createIntegrityManifest(root, { targets: ['protected.txt'] })));
  const service = new AppService({ baseDirectory, dataDirectory, downloadsDirectory, selfProtectionOptions: { baseDirectory: root, manifestPath, targets: ['protected.txt'] } });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  await service.init();
  const report = await service.runIntegrityAudit();
  assert.equal(report.reportAvailable, true);
  assert.equal(report.summary.verified, 1);
  const bootstrap = await service.getBootstrap();
  assert.equal(bootstrap.integrity.reportAvailable, true);
  const latest = await service.getLatestIntegrityReport('json');
  assert.equal(JSON.parse(await fs.readFile(latest.path, 'utf8')).summary.healthy, true);
});

test('network protection requires explicit block mode and persists reversible state', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-network-protection-'));
  const dataDirectory = path.join(root, 'data'); const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const calls = [];
  const service = new AppService({ baseDirectory, dataDirectory, downloadsDirectory, networkProtectionOptions: { runner: async request => { calls.push(request); return request.operation === 'apply' ? { Applied: 1, Rules: ['rule-a'] } : {}; } } });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  await service.init();
  await assert.rejects(service.applyNetworkProtection(), /bloqueo reversible/i);
  await service.saveSettings({ networkProtectionMode: 'block' });
  service.networkIndicators = { ips: ['203.0.113.10'], domains: ['bad.example'] };
  const applied = await service.applyNetworkProtection();
  assert.equal(applied.active, true);
  assert.equal(applied.addressesBlocked, 1);
  assert.equal(applied.domainsPending, 1);
  const removed = await service.removeNetworkProtection();
  assert.equal(removed.active, false);
  assert.deepEqual(calls.map(call => call.operation), ['apply', 'remove']);
});

test('AppService activates verified definitions and exposes a reversible rollback state', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-definition-service-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    definitionUpdateOptions: { publicKeys: { 'test-release': publicKey.export({ type: 'spki', format: 'pem' }) } }
  });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  await service.init();
  const payload = Buffer.from(JSON.stringify({ version: 4, generatedAt: '2026-08-20T04:00:00.000Z', sha256: {}, puaSha256: {}, patterns: [] }));
  const envelope = { schemaVersion: 1, keyId: 'test-release', payloadBase64: payload.toString('base64'), signatureBase64: crypto.sign(null, payload, privateKey).toString('base64') };
  const updated = await service.applyDefinitionBundle(envelope);
  assert.equal(updated.currentVersion, 4);
  assert.equal((await service.getBootstrap()).definitions.updates.source, 'updated');
  assert.equal(service.engine.definitions.version, 4);
  const rolledBack = await service.rollbackDefinitions();
  assert.equal(rolledBack.currentVersion, 3);
  assert.equal((await service.getBootstrap()).definitions.updates.source, 'bundled');
});

test('AppService applies a maintainer-signed daily definition feed through the same update gate', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-definition-feed-service-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const payload = Buffer.from(JSON.stringify({ version: 4, generatedAt: '2026-08-20T05:00:00.000Z', sha256: {}, puaSha256: {}, patterns: [] }));
  const envelope = { schemaVersion: 1, keyId: 'test-release', payloadBase64: payload.toString('base64'), signatureBase64: crypto.sign(null, payload, privateKey).toString('base64') };
  const calls = [];
  const service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    definitionUpdateOptions: { publicKeys: { 'test-release': publicKey.export({ type: 'spki', format: 'pem' }) } },
    definitionFeedOptions: {
      config: { enabled: true, url: 'https://updates.example.test/definitions.bundle.json' },
      fetchImpl: async (_url, options) => { calls.push(options); return { ok: true, status: 200, headers: { get: () => '"v4"' }, text: async () => JSON.stringify(envelope) }; }
    }
  });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  await service.init();
  const result = await service.checkDefinitionFeed({ force: true });
  assert.equal(result.feedResult, 'applied');
  assert.equal(result.currentVersion, 4);
  assert.equal(service.engine.definitions.version, 4);
  assert.equal(calls.length, 1);
});

test('AppService keeps reputation lookups opt-in and exposes the normalized latest result', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-threat-intel-service-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const calls = [];
  const service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    threatIntelOptions: {
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        return { ok: true, status: 200, text: async () => JSON.stringify({ FileName: 'known.exe', source: 'NSRL', 'hashlookup:trust': 90 }) };
      }
    }
  });
  t.after(async () => { await service.shutdown(); await fs.rm(root, { recursive: true, force: true }); });
  await service.init();
  await assert.rejects(service.queryThreatIntel('b'.repeat(64)), error => error.code === 'REPUTATION_NOT_ENABLED');
  await service.saveSettings({ reputationSharingEnabled: true });
  const result = await service.queryThreatIntel('b'.repeat(64));
  assert.equal(result.verdict, 'known-file-context');
  assert.equal(result.confidence, 90);
  assert.equal(calls.length, 1);
  assert.equal((await service.getBootstrap()).threatIntel.latest.verdict, 'known-file-context');
});
