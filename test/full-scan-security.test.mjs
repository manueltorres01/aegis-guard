import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppService } from '../src/app-service.mjs';
import { createHarmlessSimulation } from '../src/simulator.mjs';

const baseDirectory = fileURLToPath(new URL('..', import.meta.url));

test('full scan excludes only the canonical quarantine vault, not all Aegis data', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-full-exclude-'));
  const drive = path.join(root, 'drive');
  const dataDirectory = path.join(drive, 'aegis-data');
  const downloadsDirectory = path.join(root, 'downloads');
  await Promise.all([
    fs.mkdir(dataDirectory, { recursive: true }),
    fs.mkdir(downloadsDirectory, { recursive: true })
  ]);
  await fs.writeFile(path.join(drive, 'ordinary.txt'), 'ordinary fixture');
  const visibleDataSimulation = await createHarmlessSimulation(path.join(dataDirectory, 'visible-data'));
  const excludedSimulation = await createHarmlessSimulation(path.join(dataDirectory, 'quarantine', 'must-not-scan'));

  const service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    driveRootsProvider: async () => [drive]
  });
  t.after(async () => {
    await service.shutdown();
    await fs.rm(root, { recursive: true, force: true });
  });

  await service.init();
  const report = await service.startScan({ mode: 'full', autoQuarantine: false });
  assert.equal(report.summary.scanned, 2);
  assert.equal(report.summary.malicious, 1);
  assert.equal(report.results.some(result => result.path === visibleDataSimulation), true);
  assert.equal(report.results.some(result => result.path === excludedSimulation), false);
});

test('cancelled full scans retain bounded findings for manual isolation', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-full-cancel-'));
  const drive = path.join(root, 'drive');
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await Promise.all([
    fs.mkdir(drive),
    fs.mkdir(dataDirectory),
    fs.mkdir(downloadsDirectory)
  ]);
  const simulation = await createHarmlessSimulation(drive);
  let service;
  service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    driveRootsProvider: async () => [drive],
    emit: event => {
      if (event.type === 'scan-detection') service.cancelScan(event.payload.scanId);
    }
  });
  t.after(async () => {
    await service.shutdown();
    await fs.rm(root, { recursive: true, force: true });
  });

  await service.init();
  const report = await service.startScan({ mode: 'full', autoQuarantine: false });
  assert.equal(report.cancelled, true);
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].path, simulation);
  const isolated = await service.isolateResult(report.scanId, report.results[0].resultId);
  assert.equal(typeof isolated.id, 'string');
  await assert.rejects(fs.access(simulation), { code: 'ENOENT' });
});
