import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SelfProtectionAuditor, createIntegrityManifest, writeSelfProtectionReport } from '../src/self-protection-audit.mjs';

test('self-protection audit detects modified, missing and verified components', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-integrity-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, 'definitions'), { recursive: true });
  await fs.writeFile(path.join(root, 'config.txt'), 'original');
  await fs.writeFile(path.join(root, 'missing.txt'), 'temporary');
  const manifest = await createIntegrityManifest(root, { targets: ['config.txt', 'missing.txt'] });
  await fs.writeFile(path.join(root, 'definitions', 'integrity-manifest.json'), JSON.stringify(manifest));
  await fs.writeFile(path.join(root, 'config.txt'), 'modified');
  await fs.rm(path.join(root, 'missing.txt'));
  const report = await new SelfProtectionAuditor({ baseDirectory: root, targets: ['config.txt', 'missing.txt'] }).audit();
  assert.equal(report.available, true);
  assert.equal(report.summary.modified, 1);
  assert.equal(report.summary.missing, 1);
  assert.equal(report.summary.healthy, false);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-integrity-report-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const files = await writeSelfProtectionReport(directory, report);
  assert.equal(JSON.parse(await fs.readFile(files.json, 'utf8')).summary.modified, 1);
  assert.match(await fs.readFile(files.csv, 'utf8'), /modified/);
});

test('self-protection audit fails closed when the local manifest is absent', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-integrity-missing-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const report = await new SelfProtectionAuditor({ baseDirectory: root, targets: [] }).audit();
  assert.equal(report.available, false);
  assert.equal(report.enforcement.blocking, false);
});
