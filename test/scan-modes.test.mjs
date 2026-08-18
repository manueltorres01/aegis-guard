import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppService } from '../src/app-service.mjs';
import { createHarmlessSimulation } from '../src/simulator.mjs';

const baseDirectory = fileURLToPath(new URL('..', import.meta.url));

async function createFixture(t, prefix) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  const downloadsDirectory = path.join(root, 'downloads');
  const defaultDataDirectory = path.join(root, 'data');
  const services = [];
  await fs.mkdir(downloadsDirectory, { recursive: true });
  t.after(async () => {
    await Promise.allSettled(services.map(service => service.shutdown()));
    await fs.rm(root, { recursive: true, force: true });
  });
  return {
    root,
    downloadsDirectory,
    defaultDataDirectory,
    createService(options = {}) {
      const service = new AppService({
        baseDirectory,
        dataDirectory: defaultDataDirectory,
        downloadsDirectory,
        ...options
      });
      services.push(service);
      return service;
    }
  };
}

async function createSparseFile(file, size) {
  const handle = await fs.open(file, 'w');
  try { await handle.truncate(size); }
  finally { await handle.close(); }
}

test('quick scan is bounded to regular files at the top level of Downloads', async t => {
  const fixture = await createFixture(t, 'aegis-mode-quick-');
  const topLevel = path.join(fixture.downloadsDirectory, 'top-level.txt');
  const hidden = path.join(fixture.downloadsDirectory, '.hidden-download.txt');
  const oversized = path.join(fixture.downloadsDirectory, 'oversized.bin');
  await Promise.all([
    fs.writeFile(topLevel, 'ordinary top-level fixture'),
    fs.writeFile(hidden, 'hidden top-level fixture'),
    createSparseFile(oversized, 129 * 1024 * 1024)
  ]);
  const nestedSimulation = await createHarmlessSimulation(path.join(fixture.downloadsDirectory, 'nested'));
  const outsideSimulation = await createHarmlessSimulation(path.join(fixture.root, 'outside'));
  const events = [];
  const service = fixture.createService({ emit: event => events.push(event) });
  await service.init();

  const report = await service.startScan({ mode: 'quick', target: 'quick', autoQuarantine: false });
  assert.equal(report.mode, 'quick');
  assert.equal(report.path, path.resolve(fixture.downloadsDirectory));
  assert.equal(report.summary.rootsScanned, 1);
  assert.equal(report.summary.scanned, 3);
  assert.equal(report.summary.skipped, 1);
  assert.equal(report.summary.malicious, 0);
  assert.equal(report.summary.errors, 0);
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].path, path.resolve(oversized));
  assert.equal(report.results[0].verdict, 'skipped');
  assert.equal(report.results.some(result => result.path === nestedSimulation), false);
  assert.equal(report.results.some(result => result.path === outsideSimulation), false);
  const finalProgress = events.filter(event =>
    event.type === 'scan-progress' && event.payload.scanId === report.scanId
  ).at(-1)?.payload;
  assert.equal(finalProgress.total, null);
  assert.equal(finalProgress.filesDiscovered, 3);
  assert.equal(finalProgress.completed, 3);
});

test('deep scan includes hidden, excluded-name and deeply nested files but stays inside its root', async t => {
  const fixture = await createFixture(t, 'aegis-mode-deep-');
  const selectedRoot = path.join(fixture.root, 'selected');
  const privateData = path.join(selectedRoot, 'aegis-private-data');
  await fs.mkdir(selectedRoot);

  const visibleSimulation = await createHarmlessSimulation(selectedRoot);
  const hiddenSimulation = path.join(selectedRoot, '.hidden-simulation.txt');
  await fs.rename(visibleSimulation, hiddenSimulation);
  let deepDirectory = selectedRoot;
  for (let depth = 0; depth < 24; depth++) deepDirectory = path.join(deepDirectory, `depth-${depth}`);
  const deepSimulation = await createHarmlessSimulation(deepDirectory);
  const gitSimulation = await createHarmlessSimulation(path.join(selectedRoot, '.git'));
  const modulesSimulation = await createHarmlessSimulation(path.join(selectedRoot, 'node_modules'));
  const excludedSimulation = await createHarmlessSimulation(path.join(privateData, 'fixture'));
  const outsideRoot = path.join(fixture.root, 'outside');
  const outsideSimulation = await createHarmlessSimulation(outsideRoot);
  const linkedOutside = path.join(selectedRoot, 'linked-outside');
  let linkCreated = false;
  try {
    await fs.symlink(outsideRoot, linkedOutside, process.platform === 'win32' ? 'junction' : 'dir');
    linkCreated = true;
  } catch (error) {
    if (!['EPERM', 'EACCES', 'ENOSYS'].includes(error.code)) throw error;
  }

  const events = [];
  const service = fixture.createService({
    dataDirectory: privateData,
    emit: event => events.push(event)
  });
  await service.init();
  const report = await service.startScan({ mode: 'deep', target: selectedRoot, autoQuarantine: false });

  const expectedDetections = new Set([
    path.resolve(hiddenSimulation),
    path.resolve(deepSimulation),
    path.resolve(gitSimulation),
    path.resolve(modulesSimulation),
    path.resolve(excludedSimulation)
  ]);
  assert.equal(report.mode, 'deep');
  assert.equal(report.path, path.resolve(selectedRoot));
  assert.equal(report.summary.rootsScanned, 1);
  assert.equal(report.summary.scanned, expectedDetections.size);
  assert.equal(report.summary.malicious, expectedDetections.size);
  assert.equal(report.summary.skipped, 0);
  assert.equal(report.summary.errors, 0);
  assert.equal(report.results.length, expectedDetections.size);
  assert.deepEqual(new Set(report.results.map(result => result.path)), expectedDetections);
  assert.equal(report.results.some(result => result.path === excludedSimulation), true);
  assert.equal(report.results.some(result => result.path === outsideSimulation), false);
  if (linkCreated) {
    assert.ok(report.summary.traversalSkipped >= 1);
    assert.ok(report.summary.linksSkipped >= 1);
  }

  const progress = events.filter(event =>
    event.type === 'scan-progress' && event.payload.scanId === report.scanId
  ).map(event => event.payload);
  assert.ok(progress.length >= 1);
  assert.ok(progress.every(update => update.total === null));
  for (let index = 1; index < progress.length; index++) {
    assert.ok(progress[index].filesDiscovered >= progress[index - 1].filesDiscovered);
    assert.ok(progress[index].completed >= progress[index - 1].completed);
  }

  const fileReport = await service.startScan({ mode: 'deep', target: hiddenSimulation, autoQuarantine: false });
  assert.equal(fileReport.mode, 'deep');
  assert.equal(fileReport.summary.scanned, 1);
  assert.equal(fileReport.summary.malicious, 1);

  const aliasReport = await service.startScan({ mode: 'custom', target: hiddenSimulation, autoQuarantine: false });
  assert.equal(aliasReport.mode, 'deep');
  assert.equal(aliasReport.summary.scanned, 1);
});

test('full scan streams every injected file without quick name or quantity exclusions', async t => {
  const fixture = await createFixture(t, 'aegis-mode-full-');
  const firstRoot = path.join(fixture.root, 'drive-a');
  const secondRoot = path.join(fixture.root, 'drive-b');
  await Promise.all([fs.mkdir(firstRoot), fs.mkdir(secondRoot)]);

  const ordinaryCount = 257;
  await Promise.all(Array.from({ length: ordinaryCount }, (_, index) =>
    fs.writeFile(path.join(firstRoot, `ordinary-${index}.txt`), `fixture ${index}`)
  ));
  const hiddenOriginal = await createHarmlessSimulation(firstRoot);
  const hiddenSimulation = path.join(firstRoot, '.hidden-full-simulation.txt');
  await fs.rename(hiddenOriginal, hiddenSimulation);
  const gitSimulation = await createHarmlessSimulation(path.join(firstRoot, '.git'));
  const modulesSimulation = await createHarmlessSimulation(path.join(firstRoot, 'node_modules'));
  await fs.writeFile(path.join(secondRoot, 'second-root.txt'), 'second root fixture');

  const service = fixture.createService({ driveRootsProvider: async () => [firstRoot, secondRoot] });
  await service.init();
  const report = await service.startScan({ mode: 'full', autoQuarantine: false });

  assert.equal(report.mode, 'full');
  assert.equal(report.summary.rootsScanned, 2);
  assert.equal(report.summary.scanned, ordinaryCount + 4);
  assert.equal(report.summary.malicious, 3);
  assert.equal(report.summary.skipped, 0);
  assert.equal(report.summary.errors, 0);
  assert.equal(report.resultsTruncated, 0);
  assert.deepEqual(
    new Set(report.results.map(result => result.path)),
    new Set([path.resolve(hiddenSimulation), path.resolve(gitSimulation), path.resolve(modulesSimulation)])
  );
});

test('full scan fails closed when Windows drive enumeration is unavailable', async t => {
  const fixture = await createFixture(t, 'aegis-mode-full-enumeration-');
  const events = [];
  let providerCalls = 0;
  const service = fixture.createService({
    driveRootsProvider: async () => {
      providerCalls++;
      throw new Error('Synthetic drive enumeration failure');
    },
    emit: event => events.push(event)
  });
  await service.init();

  await assert.rejects(
    service.startScan({ mode: 'full', autoQuarantine: false }),
    /drive enumeration failure/
  );
  assert.equal(providerCalls, 1);
  assert.equal(service.activeScan, null);
  assert.equal(events.some(event => event.type === 'scan-completed'), false);
  assert.equal(events.some(event => event.type === 'scan-error' && event.payload.mode === 'full'), true);
});

test('full summary remains exact and retained details prioritize higher-severity outcomes', async t => {
  const fixture = await createFixture(t, 'aegis-mode-full-retention-');
  const driveRoot = path.join(fixture.root, 'drive');
  await fs.mkdir(driveRoot);
  const service = fixture.createService({ driveRootsProvider: async () => [driveRoot] });
  await service.init();

  const skippedFindings = 5_000;
  const trailingVerdicts = ['error', 'suspicious', 'malicious'];
  const totalFindings = skippedFindings + trailingVerdicts.length;
  service.engine.scanPathStreaming = async (_root, options) => {
    options.onProgress({
      phase: 'scanning', filesDiscovered: 0, bytesDiscovered: 0,
      completed: 0, total: null, bytesCompleted: 0, currentPath: null
    });
    for (let index = 0; index < totalFindings; index++) {
      const verdict = index < skippedFindings
        ? 'skipped'
        : trailingVerdicts[index - skippedFindings];
      const score = verdict === 'malicious' ? 100 : verdict === 'suspicious' ? 40 : 0;
      const result = {
        path: path.join(driveRoot, `synthetic-${index}.bin`),
        size: 1,
        sha256: index.toString(16).padStart(64, '0'),
        score,
        verdict,
        findings: [{ id: 'test.synthetic', description: 'Synthetic retained-result boundary', score }],
        ...(verdict === 'error' ? { error: 'Synthetic file error' } : {}),
        durationMs: 0
      };
      await options.onResult(result);
    }
    options.onProgress({
      phase: 'scanning', filesDiscovered: totalFindings, bytesDiscovered: totalFindings,
      completed: totalFindings, total: null, bytesCompleted: totalFindings, currentPath: null
    });
    return {
      filesDiscovered: totalFindings,
      bytesDiscovered: totalFindings,
      completed: totalFindings,
      bytesCompleted: totalFindings,
      traversalSkipped: 0
    };
  };

  const report = await service.startScan({ mode: 'full', autoQuarantine: false });
  assert.equal(report.summary.scanned, totalFindings);
  assert.equal(report.summary.malicious, 1);
  assert.equal(report.summary.suspicious, 1);
  assert.equal(report.summary.errors, 1);
  assert.equal(report.summary.skipped, skippedFindings);
  assert.equal(report.summary.rootsScanned, 1);
  assert.equal(report.results.length, 5_000);
  assert.equal(report.resultsTruncated, totalFindings - 5_000);
  const retainedCounts = report.results.reduce((counts, result) => {
    counts[result.verdict] = (counts[result.verdict] ?? 0) + 1;
    return counts;
  }, {});
  assert.equal(retainedCounts.malicious, 1);
  assert.equal(retainedCounts.suspicious, 1);
  assert.equal(retainedCounts.error, 1);
  assert.equal(retainedCounts.skipped, 4_997);
  const retainedThreat = report.results.find(result => result.verdict === 'malicious');
  assert.match(retainedThreat?.resultId ?? '', /^[0-9a-f-]{36}$/i);
  assert.equal(service.jobs.get(report.scanId).resultMap.get(retainedThreat.resultId), retainedThreat);
});

test('deep cancellation returns a partial summary and retained finding', async t => {
  const fixture = await createFixture(t, 'aegis-mode-deep-cancel-');
  const selectedRoot = path.join(fixture.root, 'selected');
  const createdSimulation = await createHarmlessSimulation(selectedRoot);
  const simulation = path.join(selectedRoot, '000-harmless-simulation.txt');
  await fs.rename(createdSimulation, simulation);
  await Promise.all(Array.from({ length: 12 }, (_, index) =>
    fs.writeFile(path.join(selectedRoot, `ordinary-${index}.txt`), `fixture ${index}`)
  ));

  let service;
  service = fixture.createService({
    emit: event => {
      if (event.type === 'scan-detection' && event.payload.mode === 'deep') {
        service.cancelScan(event.payload.scanId);
      }
    }
  });
  await service.init();
  const report = await service.startScan({ mode: 'deep', target: selectedRoot, autoQuarantine: false });

  assert.equal(report.mode, 'deep');
  assert.equal(report.cancelled, true);
  assert.ok(report.summary.scanned >= 1);
  assert.ok(report.summary.scanned < 13);
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].path, path.resolve(simulation));
});

test('retained scan details have a byte budget and stored jobs remain bounded', async t => {
  const fixture = await createFixture(t, 'aegis-mode-byte-budget-');
  const driveRoot = path.join(fixture.root, 'drive');
  await fs.mkdir(driveRoot);
  const service = fixture.createService({ driveRootsProvider: async () => [driveRoot] });
  await service.init();
  const veryLongName = 'x'.repeat(32_000);
  service.engine.scanPathStreaming = async (_root, options) => {
    for (let index = 0; index < 150; index++) {
      await options.onResult({
        path: `${driveRoot}${path.sep}${index}-${veryLongName}`,
        size: 1,
        sha256: index.toString(16).padStart(64, '0'),
        score: 0,
        verdict: 'skipped',
        findings: [{ id: 'limit.test', description: 'Synthetic size-budget fixture', score: 0 }],
        durationMs: 0
      });
    }
    await options.onResult({
      path: path.join(driveRoot, 'late-malicious.exe'),
      size: 1,
      sha256: 'f'.repeat(64),
      score: 100,
      verdict: 'malicious',
      findings: [{ id: 'test.malicious', description: 'Late high-priority result', score: 100 }],
      durationMs: 0
    });
    return { filesDiscovered: 151, bytesDiscovered: 151, completed: 151, bytesCompleted: 151, traversalSkipped: 0 };
  };

  const report = await service.startScan({ mode: 'full', autoQuarantine: false });
  assert.equal(report.summary.scanned, 151);
  assert.ok(report.results.length < 151);
  assert.ok(report.resultsTruncated > 0);
  assert.ok(report.results.some(result => result.verdict === 'malicious'));
  assert.ok(JSON.stringify(report.results).length * 2 < 9 * 1024 * 1024);

  service.engine.scanPathStreaming = async (_root, options) => {
    await options.onResult({
      path: path.join(driveRoot, 'small-error.bin'), verdict: 'error', score: 0,
      findings: [], error: 'Synthetic error', durationMs: 0
    });
    return { filesDiscovered: 1, bytesDiscovered: 0, completed: 1, bytesCompleted: 0, traversalSkipped: 0 };
  };
  for (let index = 0; index < 6; index++) await service.startScan({ mode: 'full', autoQuarantine: false });
  assert.equal(service.jobs.size, 4);
});
