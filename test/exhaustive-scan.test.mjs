import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ScanEngine } from '../src/engine.mjs';

const eicar = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'ascii');

test('exhaustive scan ignores the quick size cap and matches a signature across chunk boundaries', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-exhaustive-chunk-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'boundary-fixture.bin');
  const payload = Buffer.concat([
    Buffer.alloc(60, 0x41),
    eicar,
    Buffer.from('complete-file-tail', 'ascii')
  ]);
  await fs.writeFile(file, payload);
  const expectedSha256 = crypto.createHash('sha256').update(payload).digest('hex');
  const engine = new ScanEngine({
    maxFileSizeMb: 0.00001,
    definitions: {
      sha256: { [expectedSha256]: 'Complete fixture hash' },
      patterns: [{
        id: 'test.eicar-boundary',
        name: 'EICAR boundary fixture',
        score: 100,
        literalBase64: eicar.toString('base64')
      }]
    }
  });

  const bounded = await engine.scanFile(file);
  assert.equal(bounded.verdict, 'skipped');
  assert.equal(bounded.sha256, null);
  assert.ok(bounded.findings.some(finding => finding.id === 'limit.size'));

  const exhaustive = await engine.scanFileExhaustive(file, { chunkSize: 64 });
  assert.equal(exhaustive.verdict, 'malicious');
  assert.equal(exhaustive.sha256, expectedSha256);
  assert.ok(exhaustive.findings.some(finding => finding.id === 'test.eicar-boundary'));
  assert.ok(exhaustive.findings.some(finding => finding.id === 'signature.sha256'));
});
