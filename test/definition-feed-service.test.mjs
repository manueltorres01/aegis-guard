import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DefinitionFeedService } from '../src/definition-feed-service.mjs';

function response(status, body, headers = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: name => headers[String(name).toLowerCase()] ?? null },
    text: async () => JSON.stringify(body)
  };
}

test('definition feed applies a signed envelope once and uses conditional daily requests', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-definition-feed-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  let now = new Date('2026-08-20T08:00:00.000Z');
  const calls = [];
  let applied = 0;
  const service = new DefinitionFeedService({
    dataDirectory: root,
    config: { enabled: true, url: 'https://updates.example.test/definitions.bundle.json', intervalHours: 24 },
    clock: () => now,
    fetchImpl: async (_url, options) => {
      calls.push(options);
      return calls.length === 1
        ? response(200, { schemaVersion: 1, keyId: 'release', payloadBase64: 'YQ==', signatureBase64: 'Yg==' }, { etag: '"v4"', 'last-modified': 'Thu, 20 Aug 2026 08:00:00 GMT' })
        : response(304, null);
    },
    applyEnvelope: async envelope => { applied++; assert.equal(envelope.keyId, 'release'); return { currentVersion: 4 }; }
  });
  await service.init();
  const first = await service.check();
  assert.equal(first.result, 'applied');
  assert.equal(applied, 1);
  assert.equal(first.feedResult, undefined);
  assert.equal(first.nextCheckAt, '2026-08-21T08:00:00.000Z');
  assert.equal(first.etagStored, true);
  const skipped = await service.check();
  assert.equal(skipped.result, 'not-due');
  now = new Date('2026-08-21T08:00:00.000Z');
  const second = await service.check();
  assert.equal(second.result, 'not-modified');
  assert.equal(applied, 1);
  assert.equal(calls[1].headers['If-None-Match'], '"v4"');
  assert.equal(calls[1].headers['If-Modified-Since'], 'Thu, 20 Aug 2026 08:00:00 GMT');
});

test('definition feed backs off after transport or payload errors and never applies untrusted data itself', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-definition-feed-failure-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  let now = new Date('2026-08-20T08:00:00.000Z');
  let calls = 0;
  let applied = 0;
  const service = new DefinitionFeedService({
    dataDirectory: root,
    config: { enabled: true, url: 'https://updates.example.test/definitions.bundle.json', intervalHours: 24 },
    clock: () => now,
    fetchImpl: async () => { calls++; throw new Error('timeout'); },
    applyEnvelope: async () => { applied++; }
  });
  await service.init();
  const failed = await service.check();
  assert.equal(failed.result, 'error');
  assert.equal(failed.consecutiveFailures, 1);
  assert.equal(applied, 0);
  const blockedByBackoff = await service.check();
  assert.equal(blockedByBackoff.result, 'not-due');
  assert.equal(calls, 1);
  assert.equal(service.status().configured, true);
});

test('definition feed is disabled by default and rejects non-HTTPS endpoints', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-definition-feed-disabled-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const service = new DefinitionFeedService({ dataDirectory: root, config: { enabled: true, url: 'http://localhost/feed.json' } });
  await service.init();
  const result = await service.check({ force: true });
  assert.equal(result.result, 'not-configured');
  assert.equal(service.status().configured, false);
});
