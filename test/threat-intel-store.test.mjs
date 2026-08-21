import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ThreatIntelStore } from '../src/threat-intel-store.mjs';

const HASH = 'a'.repeat(64);

function response(value, status = 200) {
  const text = JSON.stringify(value);
  return { ok: status >= 200 && status < 300, status, text: async () => text };
}

test('threat intel requires explicit network consent and stores a bounded CIRCL cache', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-threat-intel-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  let calls = 0;
  const store = new ThreatIntelStore({
    dataDirectory: root,
    fetchImpl: async url => {
      calls++;
      assert.match(url, /hashlookup\.circl\.lu\/lookup\/sha256/);
      return response({ FileName: 'known.exe', FileSize: 42, source: 'NSRL', 'hashlookup:trust': 92 });
    }
  });
  await store.init();
  const denied = await store.lookupSha256(HASH);
  assert.equal(denied.verdict, 'unavailable');
  assert.equal(calls, 0);
  const result = await store.lookupSha256(HASH, { allowNetwork: true });
  assert.equal(result.verdict, 'known-file-context');
  assert.equal(result.confidence, 92);
  assert.equal(calls, 1);
  const cached = await store.lookupSha256(HASH, { allowNetwork: true });
  assert.equal(cached.queriedAt, result.queriedAt);
  assert.equal(calls, 1);
  const persisted = JSON.parse(await fsp.readFile(path.join(root, 'threat-intel', 'cache.json'), 'utf8'));
  assert.equal(Object.keys(persisted.entries).length, 1);
});

test('threat intel normalizes abuse.ch matches without uploading files', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-threat-intel-abusech-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const requests = [];
  const store = new ThreatIntelStore({
    dataDirectory: root,
    abuseChAuthKey: 'test-key',
    config: { circl: { enabled: false }, malwareBazaar: { enabled: true }, threatFox: { enabled: true } },
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      if (url.includes('mb-api.abuse.ch')) return response({ query_status: 'ok', data: [{ signature: 'TestRAT', first_seen: '2026-08-20 10:00:00', tags: ['exe'] }] });
      return response({ query_status: 'ok', data: [{ malware_printable: 'TestRAT', confidence_level: 80 }] });
    }
  });
  await store.init();
  const result = await store.lookupSha256(HASH, { allowNetwork: true });
  assert.equal(result.verdict, 'known-malicious');
  assert.equal(result.confidence, 100);
  assert.equal(requests.length, 2);
  assert.equal(requests.every(request => !String(request.options?.body ?? '').includes('file')), true);
  assert.equal(requests.every(request => request.options?.headers?.['Auth-Key'] === 'test-key'), true);
});

test('threat intel rate limits each provider and rejects invalid hashes', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-threat-intel-limit-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const store = new ThreatIntelStore({ dataDirectory: root, maxRequestsPerMinute: 1, fetchImpl: async () => response({}, 404) });
  await store.init();
  await assert.rejects(store.lookupSha256('not-a-hash'), /SHA-256/);
  const first = await store.lookupSha256(HASH, { allowNetwork: true, force: true });
  assert.equal(first.sources[0].status, 'not-found');
  const second = await store.lookupSha256(HASH, { allowNetwork: true, force: true });
  assert.equal(second.sources[0].status, 'rate-limited');
});
