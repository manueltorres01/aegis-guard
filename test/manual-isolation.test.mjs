import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppService } from '../src/app-service.mjs';
import { createHarmlessSimulation } from '../src/simulator.mjs';

const baseDirectory = fileURLToPath(new URL('..', import.meta.url));

test('manual quarantine resolves a stored scan result instead of accepting a path', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-manual-'));
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory);
  const service = new AppService({
    baseDirectory,
    dataDirectory: path.join(root, 'data'),
    downloadsDirectory
  });
  await service.init();
  t.after(async () => {
    await service.shutdown();
    await fs.rm(root, { recursive: true, force: true });
  });

  const sample = await createHarmlessSimulation(downloadsDirectory);
  const report = await service.startScan({ target: sample, autoQuarantine: false });
  const result = report.results[0];
  await assert.rejects(service.isolateResult(report.scanId, '182452d6-a237-4a12-9552-f29849535227'), /Unknown scan result/);
  assert.equal((await fs.stat(sample)).isFile(), true);

  const isolated = await service.isolateResult(report.scanId, result.resultId);
  assert.equal(isolated.sha256, result.sha256);
  await assert.rejects(fs.access(sample), { code: 'ENOENT' });
  assert.equal((await service.listQuarantine()).items.length, 1);
});

test('a detection can be isolated while its deep scan is still active', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-active-isolation-'));
  const downloadsDirectory = path.join(root, 'downloads');
  const scanRoot = path.join(root, 'selected');
  await Promise.all([fs.mkdir(downloadsDirectory), fs.mkdir(scanRoot)]);
  let isolationPromise;
  let service;
  service = new AppService({
    baseDirectory,
    dataDirectory: path.join(root, 'data'),
    downloadsDirectory,
    emit: event => {
      if (event.type === 'scan-detection' && !isolationPromise) {
        isolationPromise = service.isolateResult(event.payload.scanId, event.payload.result.resultId);
      }
    }
  });
  await service.init();
  t.after(async () => {
    await service.shutdown();
    await fs.rm(root, { recursive: true, force: true });
  });

  const sample = await createHarmlessSimulation(scanRoot);
  const report = await service.startScan({ mode: 'deep', target: scanRoot, autoQuarantine: false });
  assert.ok(isolationPromise, 'scan-detection should expose an active job result');
  const isolated = await isolationPromise;
  assert.equal(isolated.sha256, report.results[0].sha256);
  await assert.rejects(fs.access(sample), { code: 'ENOENT' });
  assert.equal((await service.listQuarantine()).items.length, 1);
});
