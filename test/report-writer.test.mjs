import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ScanReportWriter } from '../src/report-writer.mjs';

test('complete report writer produces valid JSON and spreadsheet-safe CSV', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-report-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const writer = await new ScanReportWriter({
    directory,
    scanId: '182452d6-a237-4a12-9552-f29849535227',
    mode: 'deep',
    target: 'C:\\Selected',
    startedAt: Date.now()
  }).init();
  await writer.append({
    path: '=HYPERLINK("https://invalid.example")', verdict: 'suspicious', score: 28,
    size: 42, sha256: 'a'.repeat(64), findings: [{ id: 'test', description: 'Review', score: 28 }],
    trust: { status: 'valid', organization: 'Example Publisher', applicationVerified: true }
  });
  await writer.append({ path: 'C:\\ordinary.txt', verdict: 'clean', score: 0, findings: [] });
  const completedAt = new Date().toISOString();
  const report = await writer.finalize({ completedAt, summary: { scanned: 2 }, resultsTruncated: 0 });

  const json = JSON.parse(await fs.readFile(path.join(directory, report.jsonFile), 'utf8'));
  const csv = await fs.readFile(path.join(directory, report.csvFile), 'utf8');
  assert.equal(json.results.length, 2);
  assert.equal(json.results[0].verifiedApplication, true);
  assert.equal(json.summary.scanned, 2);
  assert.match(csv, /"'=HYPERLINK/);
  assert.match(csv, /"verifiedApplication"/);
});
