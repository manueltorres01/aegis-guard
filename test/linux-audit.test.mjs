import test from 'node:test';
import assert from 'node:assert/strict';
import { collectLinuxAudit, parseOsRelease } from '../src/linux-audit.mjs';

test('parseOsRelease keeps only bounded distribution identity fields', () => {
  const parsed = parseOsRelease('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nSECRET=do-not-export\n');
  assert.deepEqual(parsed, { name: 'Ubuntu', id: 'ubuntu', version_id: '24.04' });
});

test('Linux audit is read-only and reports an explicit analysis-preview boundary', async () => {
  const report = await collectLinuxAudit({
    platform: 'linux',
    arch: 'x64',
    release: '6.8.0-test',
    homeDirectory: '/home/demo',
    uid: 1000,
    fsImpl: { readFile: async () => 'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n' }
  });
  assert.equal(report.available, true);
  assert.equal(report.source, 'linux-userspace');
  assert.equal(report.distribution.id, 'ubuntu');
  assert.equal(report.roots[0].path, '/home/demo');
  assert.equal(report.capabilities.enforcement, false);
  assert.match(report.limitations.join(' '), /systemd|fanotify/i);
});

test('Linux audit is unavailable on Windows instead of pretending to collect data', async () => {
  const report = await collectLinuxAudit({ platform: 'win32', homeDirectory: 'C:\\Users\\demo' });
  assert.equal(report.available, false);
  assert.equal(report.source, 'unavailable');
});
