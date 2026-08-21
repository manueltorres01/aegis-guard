import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/generate-sbom.mjs', import.meta.url));

test('SBOM generator emits SPDX metadata from the locked dependency graph', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-sbom-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const output = path.join(root, 'aegis.spdx.json');
  const run = spawnSync(process.execPath, [script, '--output', output], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const document = JSON.parse(await fsp.readFile(output, 'utf8'));
  assert.equal(document.spdxVersion, 'SPDX-2.3');
  assert.equal(document.packages[0].name, 'aegis-guard');
  assert.ok(document.packages.length > 10);
  assert.ok(document.relationships.some(item => item.relationshipType === 'DEPENDS_ON'));
  assert.ok(document.packages.some(item => item.checksums?.some(checksum => checksum.algorithm === 'SHA512')));
});
