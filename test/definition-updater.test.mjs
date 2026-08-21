import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DefinitionUpdateStore } from '../src/definition-updater.mjs';

function definitions(version) {
  return { version, generatedAt: `2026-08-20T${String(version).padStart(2, '0')}:00:00.000Z`, sha256: {}, puaSha256: {}, patterns: [] };
}

function signed(value, privateKey, keyId = 'test-release') {
  const payload = Buffer.from(JSON.stringify(value));
  return { schemaVersion: 1, keyId, payloadBase64: payload.toString('base64'), signatureBase64: crypto.sign(null, payload, privateKey).toString('base64') };
}

async function fixture() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-definition-updater-'));
  await fsp.mkdir(path.join(root, 'definitions'), { recursive: true });
  await fsp.writeFile(path.join(root, 'definitions', 'signatures.json'), JSON.stringify(definitions(3)));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const store = new DefinitionUpdateStore({
    baseDirectory: root,
    dataDirectory: path.join(root, 'data'),
    publicKeys: { 'test-release': publicKey.export({ type: 'spki', format: 'pem' }) }
  });
  await store.init();
  return { root, store, privateKey };
}

test('definition updater installs a signed bundle atomically and rolls it back to the bundled release', async t => {
  const { root, store, privateKey } = await fixture();
  t.after(() => fsp.rm(root, { recursive: true, force: true }));

  assert.equal(store.status().source, 'bundled');
  const applied = await store.applyEnvelope(signed(definitions(4), privateKey));
  assert.equal(applied.currentVersion, 4);
  assert.equal(applied.source, 'updated');
  assert.equal(applied.signature.status, 'verified');
  assert.equal(applied.rollbackAvailable, true);
  assert.equal(store.currentDefinitions.version, 4);
  assert.equal((await fsp.stat(path.join(store.directory, 'active.bundle.json'))).isFile(), true);

  const rolledBack = await store.rollback();
  assert.equal(rolledBack.currentVersion, 3);
  assert.equal(rolledBack.source, 'bundled');
  assert.equal(rolledBack.rollbackAvailable, false);
  await assert.rejects(fsp.stat(path.join(store.directory, 'active.bundle.json')), { code: 'ENOENT' });
});

test('definition updater preserves one verified backup and can roll back successive versions', async t => {
  const { root, store, privateKey } = await fixture();
  t.after(() => fsp.rm(root, { recursive: true, force: true }));

  await store.applyEnvelope(signed(definitions(4), privateKey));
  await store.applyEnvelope(signed(definitions(5), privateKey));
  assert.equal(store.status().currentVersion, 5);
  assert.equal(store.status().rollbackAvailable, true);
  assert.equal((await fsp.readdir(store.backupDirectory)).length, 1);

  const first = await store.rollback();
  assert.equal(first.currentVersion, 4);
  assert.equal(first.source, 'updated');
  const second = await store.rollback();
  assert.equal(second.currentVersion, 3);
  assert.equal(second.source, 'bundled');
});

test('definition updater rejects tampering, missing trust and version rollback', async t => {
  const { root, store, privateKey } = await fixture();
  t.after(() => fsp.rm(root, { recursive: true, force: true }));

  await store.applyEnvelope(signed(definitions(4), privateKey));
  const lower = signed(definitions(4), privateKey);
  await assert.rejects(store.applyEnvelope(lower), error => error.code === 'DEFINITIONS_ROLLBACK' || /rollback/i.test(error.message));
  const tampered = signed(definitions(5), privateKey);
  tampered.payloadBase64 = Buffer.from(JSON.stringify(definitions(6))).toString('base64');
  await assert.rejects(store.applyEnvelope(tampered), /signature/i);

  const untrusted = new DefinitionUpdateStore({ baseDirectory: root, dataDirectory: path.join(root, 'other-data') });
  await untrusted.init();
  await assert.rejects(untrusted.applyEnvelope(signed(definitions(4), privateKey)), error => error.code === 'DEFINITIONS_TRUST_NOT_CONFIGURED');
});
