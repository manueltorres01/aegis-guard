import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { inspectReleaseReadiness } from '../src/release-readiness.mjs';

function baseInput(overrides = {}) {
  return {
    packageInfo: { version: '0.11.0' },
    lockInfo: { version: '0.11.0', packages: { '': { version: '0.11.0' } } },
    feedConfig: { enabled: false, url: '' },
    keysConfig: { schemaVersion: 1, keys: {} },
    workflowExists: true,
    ...overrides
  };
}

test('release readiness reports the expected warning while the feed is intentionally disabled', async () => {
  const report = await inspectReleaseReadiness(baseInput());
  assert.equal(report.status, 'ready-with-warnings');
  assert.equal(report.summary.errors, 0);
  assert.match(report.checks.find(check => check.id === 'feed-url').message, /desactivado/);
});

test('release readiness blocks an enabled feed without trusted public keys', async () => {
  const report = await inspectReleaseReadiness(baseInput({ feedConfig: { enabled: true, url: 'https://updates.example.test/feed.json' } }));
  assert.equal(report.status, 'blocked');
  assert.equal(report.checks.find(check => check.id === 'definition-trust').status, 'error');
});

test('release readiness detects private artifacts in the repository tree', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-release-readiness-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  await fsp.mkdir(path.join(root, 'secrets'), { recursive: true });
  await fsp.writeFile(path.join(root, 'secrets', 'release.pem'), 'private');
  const report = await inspectReleaseReadiness({ ...baseInput(), rootDirectory: root });
  assert.equal(report.checks.find(check => check.id === 'private-artifacts').status, 'error');
  assert.equal(report.status, 'blocked');
});

test('release readiness blocks a package and lockfile version mismatch', async () => {
  const report = await inspectReleaseReadiness(baseInput({ lockInfo: { version: '0.10.0', packages: { '': { version: '0.10.0' } } } }));
  assert.equal(report.status, 'blocked');
  assert.equal(report.checks.find(check => check.id === 'lock-version').status, 'error');
});
