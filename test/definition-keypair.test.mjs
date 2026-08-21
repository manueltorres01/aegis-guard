import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const script = fileURLToPath(new URL('../scripts/create-definition-keypair.mjs', import.meta.url));

test('definition keygen creates a private key outside the repo and merges only the public key', async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-definition-keygen-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const privateKey = path.join(root, 'private.pem');
  const publicConfig = path.join(root, 'definition-keys.json');
  await fsp.writeFile(publicConfig, JSON.stringify({ schemaVersion: 1, keys: {} }));
  const run = spawnSync(process.execPath, [script, '--key-id', 'local-test', '--private-key', privateKey, '--public-config', publicConfig], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.match(await fsp.readFile(privateKey, 'utf8'), /BEGIN PRIVATE KEY/);
  const config = JSON.parse(await fsp.readFile(publicConfig, 'utf8'));
  assert.match(config.keys['local-test'], /BEGIN PUBLIC KEY/);
  const duplicate = spawnSync(process.execPath, [script, '--key-id', 'local-test', '--private-key', path.join(root, 'second.pem'), '--public-config', publicConfig], { encoding: 'utf8' });
  assert.notEqual(duplicate.status, 0);
});
