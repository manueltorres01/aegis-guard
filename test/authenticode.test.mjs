import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAuthenticodeVerifier } from '../src/authenticode.mjs';

test('Windows Authenticode verifier distinguishes a signed OS binary from an unsigned file', {
  skip: process.platform !== 'win32'
}, async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-signature-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const unsigned = path.join(dir, 'unsigned.exe');
  await fs.writeFile(unsigned, 'MZ harmless unsigned test fixture');

  // Hosted Windows runners can take longer to initialize the Authenticode
  // provider than the product's bounded enrichment budget.
  const verify = createAuthenticodeVerifier({ timeoutMs: 20_000 });
  const signedResult = await verify(path.join(process.env.SystemRoot, 'System32', 'kernel32.dll'));
  const unsignedResult = await verify(unsigned);

  assert.equal(signedResult.status, 'valid');
  assert.equal(unsignedResult.status, 'invalid');
});
