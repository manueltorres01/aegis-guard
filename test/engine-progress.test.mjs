import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ScanEngine } from '../src/engine.mjs';

const definitions = { sha256: {}, patterns: [] };

test('scan progress remains monotonic through discovery and scanning', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-progress-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, 'nested'));
  const payloads = [
    ['alpha.txt', Buffer.alloc(11, 0x41)],
    ['beta.txt', Buffer.alloc(29, 0x42)],
    [path.join('nested', 'gamma.txt'), Buffer.alloc(47, 0x43)],
    [path.join('nested', 'delta.txt'), Buffer.alloc(83, 0x44)]
  ];
  await Promise.all(payloads.map(([name, data]) => fs.writeFile(path.join(root, name), data)));

  const progress = [];
  const resultPaths = [];
  const engine = new ScanEngine({ definitions, maxFileSizeMb: 1 });
  const results = await engine.scanPath(root, {
    concurrency: 3,
    onResult: result => resultPaths.push(result.path),
    onProgress: update => progress.push(structuredClone(update))
  });

  assert.equal(results.length, payloads.length);
  assert.equal(resultPaths.length, payloads.length);
  assert.ok(progress.length >= payloads.length + 2);

  let scanningStarted = false;
  for (let index = 0; index < progress.length; index++) {
    const current = progress[index];
    if (current.phase === 'scanning') scanningStarted = true;
    else assert.equal(scanningStarted, false, 'discovery progress must not resume after scanning starts');
    if (index === 0) continue;
    const previous = progress[index - 1];
    assert.ok(current.filesDiscovered >= previous.filesDiscovered, 'filesDiscovered regressed');
    assert.ok(current.bytesDiscovered >= previous.bytesDiscovered, 'bytesDiscovered regressed');
    assert.ok(current.completed >= previous.completed, 'completed regressed');
    assert.ok(current.bytesCompleted >= previous.bytesCompleted, 'bytesCompleted regressed');
  }

  const discovering = progress.filter(update => update.phase === 'discovering');
  const scanning = progress.filter(update => update.phase === 'scanning');
  assert.equal(discovering.at(-1).filesDiscovered, payloads.length);
  assert.ok(discovering.every(update => update.total === null && update.completed === 0));
  assert.ok(scanning.length >= 2);
  assert.ok(scanning.every(update => update.total === payloads.length));
  assert.equal(scanning[0].completed, 0);
  assert.equal(scanning.at(-1).completed, payloads.length);
  assert.equal(scanning.at(-1).bytesCompleted, payloads.reduce((sum, [, data]) => sum + data.length, 0));
});

test('scanPath rejects with AbortError when its AbortSignal is cancelled', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-cancel-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await Promise.all(Array.from({ length: 8 }, (_, index) =>
    fs.writeFile(path.join(root, `sample-${index}.txt`), Buffer.alloc(64 + index, index))));

  const controller = new AbortController();
  const progress = [];
  let resultCount = 0;
  const engine = new ScanEngine({ definitions, maxFileSizeMb: 1 });
  const scan = engine.scanPath(root, {
    concurrency: 2,
    signal: controller.signal,
    onResult: () => { resultCount++; },
    onProgress: update => {
      progress.push(structuredClone(update));
      if (update.phase === 'discovering' && update.filesDiscovered === 1) controller.abort();
    }
  });

  await assert.rejects(scan, error => error?.name === 'AbortError');
  assert.equal(controller.signal.aborted, true);
  assert.equal(resultCount, 0);
  assert.equal(progress.length, 1);
  assert.equal(progress[0].phase, 'discovering');
});

test('exhaustive streaming progress is monotonic with an indeterminate total', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-stream-progress-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const payloads = Array.from({ length: 7 }, (_, index) =>
    Buffer.alloc(41 + index * 13, 0x41 + index)
  );
  await Promise.all(payloads.map((data, index) =>
    fs.writeFile(path.join(root, `stream-${index}.txt`), data)
  ));

  const progress = [];
  const results = [];
  const engine = new ScanEngine({ definitions, maxFileSizeMb: 0.00001 });
  const totals = await engine.scanPathStreaming(root, {
    exhaustive: true,
    concurrency: 2,
    onResult: result => results.push(result),
    onProgress: update => progress.push(structuredClone(update))
  });

  assert.equal(results.length, payloads.length);
  assert.equal(totals.filesDiscovered, payloads.length);
  assert.equal(totals.completed, payloads.length);
  assert.ok(progress.length >= payloads.length + 1);
  assert.ok(progress.every(update => update.total === null));
  for (let index = 1; index < progress.length; index++) {
    assert.ok(progress[index].filesDiscovered >= progress[index - 1].filesDiscovered);
    assert.ok(progress[index].bytesDiscovered >= progress[index - 1].bytesDiscovered);
    assert.ok(progress[index].completed >= progress[index - 1].completed);
    assert.ok(progress[index].bytesCompleted >= progress[index - 1].bytesCompleted);
  }
  assert.equal(progress.at(-1).completed, payloads.length);
});

test('exhaustive streaming stops with AbortError after cancellation', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-stream-cancel-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const fileCount = 12;
  await Promise.all(Array.from({ length: fileCount }, (_, index) =>
    fs.writeFile(path.join(root, `stream-${index}.txt`), Buffer.alloc(256 + index, index))
  ));

  const controller = new AbortController();
  let resultCount = 0;
  const engine = new ScanEngine({ definitions, maxFileSizeMb: 0.00001 });
  const scan = engine.scanPathStreaming(root, {
    exhaustive: true,
    concurrency: 2,
    signal: controller.signal,
    onResult: () => { resultCount++; },
    onProgress: update => {
      if (update.completed >= 1 && !controller.signal.aborted) controller.abort();
    }
  });

  await assert.rejects(scan, error => error?.name === 'AbortError');
  assert.equal(controller.signal.aborted, true);
  assert.ok(resultCount >= 1);
  assert.ok(resultCount < fileCount);
});

test('streaming cancellation drains concurrent work before settling and emits no late callbacks', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-stream-drain-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await Promise.all([
    fs.writeFile(path.join(root, 'first.txt'), 'first fixture'),
    fs.writeFile(path.join(root, 'second.txt'), 'second fixture')
  ]);

  let releaseFirst;
  let releaseSecond;
  let markSecondStarted;
  let markAborted;
  const firstGate = new Promise(resolve => { releaseFirst = resolve; });
  const secondGate = new Promise(resolve => { releaseSecond = resolve; });
  const secondStarted = new Promise(resolve => { markSecondStarted = resolve; });
  const aborted = new Promise(resolve => { markAborted = resolve; });
  const callbacks = [];
  const controller = new AbortController();
  const engine = new ScanEngine({ definitions, maxFileSizeMb: 1 });
  let calls = 0;
  engine.scanFileExhaustive = async file => {
    const call = calls++;
    if (call === 0) await firstGate;
    else {
      markSecondStarted();
      await secondGate;
    }
    return {
      path: path.resolve(file), size: 1, sha256: '0'.repeat(64),
      score: 0, verdict: 'clean', findings: [], durationMs: 0
    };
  };

  const scan = engine.scanPathStreaming(root, {
    exhaustive: true,
    concurrency: 2,
    signal: controller.signal,
    onResult: result => callbacks.push(`result:${path.basename(result.path)}`),
    onProgress: update => {
      callbacks.push(`progress:${update.completed}`);
      if (update.completed >= 1 && !controller.signal.aborted) {
        controller.abort();
        markAborted();
      }
    }
  });
  let settled = false;
  const observed = scan.then(
    value => { settled = true; return value; },
    error => { settled = true; throw error; }
  );

  await secondStarted;
  releaseFirst();
  await aborted;
  assert.equal(controller.signal.aborted, true);
  assert.equal(settled, false, 'scan settled before the second scheduled task drained');

  releaseSecond();
  await assert.rejects(observed, error => error?.name === 'AbortError');
  assert.equal(settled, true);
  assert.equal(callbacks.filter(entry => entry.startsWith('result:')).length, 1);
  const callbacksAtSettle = callbacks.length;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(callbacks.length, callbacksAtSettle, 'a callback fired after scan settlement');
});
