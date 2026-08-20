import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppService } from '../src/app-service.mjs';
import { createHarmlessSimulation } from '../src/simulator.mjs';

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
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(events.filter(event => event.type === 'scan-warning' && event.payload.code === 'STATE_NOT_PERSISTED').length >= 2);
  assert.equal(report.summary.quarantined, 1);
});
