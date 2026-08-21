import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanEngine } from '../src/engine.mjs';
import { WatchService } from '../src/watch-service.mjs';
import { AppService } from '../src/app-service.mjs';

const baseDirectory = fileURLToPath(new URL('..', import.meta.url));
const definitions = { version: 'performance-test', sha256: {}, patterns: [] };

test('unchanged files use a bounded session cache and mutations invalidate it', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-cache-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const sample = path.join(root, 'sample.txt');
  await fs.writeFile(sample, 'first harmless payload');
  const engine = new ScanEngine({ definitions, maxFileSizeMb: 1, cacheMaxEntries: 2, cacheTtlMs: 60_000 });

  const first = await engine.scanFile(sample);
  const afterFirst = engine.getPerformanceMetrics();
  first.findings.push({ id: 'caller-mutation', description: 'must not enter cache', score: 100 });
  const second = await engine.scanFile(sample);
  const afterSecond = engine.getPerformanceMetrics();

  assert.equal(afterFirst.cacheMisses, 1);
  assert.equal(afterSecond.cacheHits, 1);
  assert.equal(afterSecond.bytesRead, afterFirst.bytesRead);
  assert.equal(second.findings.some(item => item.id === 'caller-mutation'), false);

  await fs.appendFile(sample, '!');
  await engine.scanFile(sample);
  const afterMutation = engine.getPerformanceMetrics();
  assert.equal(afterMutation.cacheMisses, 2);
  assert.ok(afterMutation.bytesRead > afterSecond.bytesRead);

  for (const name of ['second.txt', 'third.txt']) {
    const file = path.join(root, name);
    await fs.writeFile(file, name);
    await engine.scanFile(file);
  }
  assert.equal(engine.getPerformanceMetrics().cacheEntries, 2);

  engine.definitions.version = 'performance-test-updated';
  await engine.scanFile(sample);
  assert.equal(engine.getPerformanceMetrics().cacheMisses, 5);
  assert.equal(engine.getPerformanceMetrics().cacheHits, 1);
});

test('ordinary files retain only a small static probe while full hashing remains intact', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-buffer-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const sample = path.join(root, 'ordinary.txt');
  const payload = Buffer.alloc(2 * 1024 * 1024, 0x41);
  await fs.writeFile(sample, payload);
  const engine = new ScanEngine({ definitions, maxFileSizeMb: 4, cacheMaxEntries: 0 });

  const result = await engine.scanFileExhaustive(sample, { chunkSize: 128 * 1024 });
  const metrics = engine.getPerformanceMetrics();

  assert.equal(result.size, payload.length);
  assert.equal(metrics.bytesRead, payload.length);
  assert.ok(metrics.peakWorkingBufferBytes < 512 * 1024);
});

test('watch events are coalesced behind one bounded pending queue', () => {
  const events = [];
  const watcher = new WatchService({
    engine: {},
    quarantine: {},
    emit: event => events.push(event),
    debounceMs: 500,
    maxQueue: 2,
    maxPendingEvents: 2,
    warningIntervalMs: 30_000
  });
  const session = {};
  const enqueued = [];
  watcher.session = session;
  watcher.enqueue = file => enqueued.push(file);

  assert.equal(watcher.schedule('C:\\first.txt', session, 1_000), true);
  assert.equal(watcher.schedule('C:\\first.txt', session, 1_100), true);
  assert.equal(watcher.schedule('C:\\second.txt', session, 1_100), true);
  assert.equal(watcher.schedule('C:\\overflow.txt', session, 1_100), false);
  clearTimeout(watcher.pendingTimer);
  watcher.pendingTimer = null;
  watcher.flushPendingCandidates(1_700);

  assert.deepEqual(enqueued.sort(), ['C:\\first.txt', 'C:\\second.txt']);
  assert.equal(events.filter(event => event.type === 'monitor-warning').length, 1);
  assert.deepEqual(watcher.status(), {
    active: true,
    pendingEvents: 0,
    queueDepth: 0,
    queueLimit: 2,
    pendingLimit: 2,
    eventsReceived: 4,
    eventsCoalesced: 1,
    eventsDropped: 1,
    filesInspected: 0,
    peakPendingEvents: 2,
    peakQueueDepth: 0
  });
});

test('background detections batch state persistence and shutdown can flush them', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-persistence-batch-'));
  const dataDirectory = path.join(root, 'data');
  const downloadsDirectory = path.join(root, 'downloads');
  await fs.mkdir(downloadsDirectory, { recursive: true });
  const service = new AppService({
    baseDirectory,
    dataDirectory,
    downloadsDirectory,
    statePersistenceDelayMs: 5_000
  });
  t.after(async () => {
    await service.shutdown();
    await fs.rm(root, { recursive: true, force: true });
  });
  await service.init();
  let writes = 0;
  service.persistState = async () => { writes++; };
  const result = { path: path.join(downloadsDirectory, 'notice.bin'), verdict: 'suspicious', score: 28, findings: [] };

  service.handleProtectionEvent({ type: 'monitor-result', payload: { result } });
  service.handleRansomwareEvent({
    type: 'ransomware-audit-alert',
    payload: { id: 'audit-1', at: new Date().toISOString(), kind: 'rate', severity: 'medium', rootLabel: 'Documents' }
  });
  assert.equal(writes, 0);
  await service.flushScheduledPersistence();
  assert.equal(writes, 1);
});
