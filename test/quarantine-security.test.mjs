import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Quarantine } from '../src/quarantine.mjs';

function scanRecord(data) {
  return {
    sha256: crypto.createHash('sha256').update(data).digest('hex'),
    verdict: 'malicious',
    score: 100,
    findings: [{ id: 'test.fixture', description: 'Harmless test fixture', score: 100 }]
  };
}

test('authenticated metadata tampering prevents restore and creates no destination', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-metadata-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const vault = path.join(root, 'vault');
  const source = path.join(root, 'sample.bin');
  const destination = path.join(root, 'restored', 'sample.bin');
  const payload = Buffer.from('inert quarantine authentication fixture');
  await fs.writeFile(source, payload);

  const quarantine = new Quarantine(vault);
  const item = await quarantine.isolate(source, scanRecord(payload));
  const metadataFile = path.join(vault, `${item.id}.json`);
  const metadata = JSON.parse(await fs.readFile(metadataFile, 'utf8'));
  metadata.score = 1;
  await fs.writeFile(metadataFile, JSON.stringify(metadata, null, 2));

  await assert.rejects(
    quarantine.restore(item.id, destination),
    error => /authentic|unsupported state/i.test(error?.message ?? '')
  );
  await assert.rejects(fs.access(destination), { code: 'ENOENT' });
  assert.equal((await fs.stat(path.join(vault, `${item.id}.bin`))).isFile(), true);
  assert.equal((await fs.stat(metadataFile)).isFile(), true);
});

test('restore refuses to overwrite an existing destination', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-overwrite-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const vault = path.join(root, 'vault');
  const source = path.join(root, 'sample.bin');
  const destination = path.join(root, 'existing.bin');
  const payload = Buffer.from('inert quarantine no-overwrite fixture');
  const existing = Buffer.from('keep this existing destination');
  await fs.writeFile(source, payload);
  await fs.writeFile(destination, existing);

  const quarantine = new Quarantine(vault);
  const item = await quarantine.isolate(source, scanRecord(payload));
  await assert.rejects(
    quarantine.restore(item.id, destination),
    /Refusing to overwrite existing file/
  );

  assert.deepEqual(await fs.readFile(destination), existing);
  assert.equal((await fs.stat(path.join(vault, `${item.id}.bin`))).isFile(), true);
  assert.equal((await fs.stat(path.join(vault, `${item.id}.json`))).isFile(), true);
});

test('format 2 quarantine streams a multi-chunk file and restores it byte-for-byte', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-streaming-quarantine-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const vault = path.join(root, 'vault');
  const source = path.join(root, 'multi-chunk.bin');
  const destination = path.join(root, 'restored', 'multi-chunk.bin');
  const payload = Buffer.alloc(2 * 1024 * 1024 + 137);
  for (let index = 0; index < payload.length; index++) payload[index] = (index * 31 + 17) & 0xff;
  await fs.writeFile(source, payload);

  const quarantine = new Quarantine(vault);
  const item = await quarantine.isolate(source, scanRecord(payload));
  assert.equal(item.format, 2);
  assert.equal((await fs.stat(path.join(vault, `${item.id}.bin`))).size, payload.length);
  await assert.rejects(fs.access(source), { code: 'ENOENT' });

  const restored = await quarantine.restore(item.id, destination);
  assert.equal(restored, path.resolve(destination));
  assert.deepEqual(await fs.readFile(destination), payload);
  assert.deepEqual(await fs.readdir(path.dirname(destination)), [path.basename(destination)]);
  await assert.rejects(fs.access(path.join(vault, `${item.id}.bin`)), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(vault, `${item.id}.json`)), { code: 'ENOENT' });
});

test('ciphertext tampering fails authentication without exposing a destination or plaintext temporary', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-streaming-tamper-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const vault = path.join(root, 'vault');
  const source = path.join(root, 'tamper.bin');
  const destination = path.join(root, 'restored', 'tamper.bin');
  const payload = Buffer.alloc(1024 * 1024 + 73, 0x5a);
  await fs.writeFile(source, payload);

  const quarantine = new Quarantine(vault);
  const item = await quarantine.isolate(source, scanRecord(payload));
  const binFile = path.join(vault, `${item.id}.bin`);
  const handle = await fs.open(binFile, 'r+');
  try {
    const byte = Buffer.alloc(1);
    await handle.read(byte, 0, 1, 1024 * 1024 - 1);
    byte[0] ^= 0xff;
    await handle.write(byte, 0, 1, 1024 * 1024 - 1);
  } finally {
    await handle.close();
  }

  await assert.rejects(
    quarantine.restore(item.id, destination),
    error => /authentic|unsupported state/i.test(error?.message ?? '')
  );
  await assert.rejects(fs.access(destination), { code: 'ENOENT' });
  assert.deepEqual(await fs.readdir(path.dirname(destination)), []);
  assert.equal((await fs.stat(binFile)).isFile(), true);
  assert.equal((await fs.stat(path.join(vault, `${item.id}.json`))).isFile(), true);
});

test('a staged-source removal failure rolls back committed artifacts and restores the original', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-quarantine-rollback-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const vault = path.join(root, 'vault');
  const source = path.join(root, 'rollback.bin');
  const payload = Buffer.alloc(1024 * 1024 + 19, 0x3c);
  await fs.writeFile(source, payload);
  const injected = new Error('Injected staged removal failure');
  injected.code = 'EACCES';
  const quarantine = new Quarantine(vault, {
    removeStaged: async () => { throw injected; }
  });

  await assert.rejects(quarantine.isolate(source, scanRecord(payload)), /Injected staged removal failure/);
  assert.deepEqual(await fs.readFile(source), payload);
  const vaultNames = await fs.readdir(vault);
  assert.deepEqual(vaultNames, ['.key']);
  assert.equal((await fs.readdir(root)).some(name => name.endsWith('.quarantine-tmp')), false);
});

test('quarantine inventory is bounded and accounts for corrupt and oversized metadata', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-quarantine-list-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const vault = path.join(root, 'vault');
  const quarantine = new Quarantine(vault);
  const validIds = new Set();

  for (let index = 0; index < 3; index++) {
    const payload = Buffer.from(`bounded inventory fixture ${index}`);
    const source = path.join(root, `valid-${index}.bin`);
    await fs.writeFile(source, payload);
    const item = await quarantine.isolate(source, scanRecord(payload));
    validIds.add(item.id);
  }

  const missingPayload = Buffer.from('metadata with a missing encrypted payload');
  const missingPayloadSource = path.join(root, 'missing-payload.bin');
  await fs.writeFile(missingPayloadSource, missingPayload);
  const missingPayloadItem = await quarantine.isolate(missingPayloadSource, scanRecord(missingPayload));
  await fs.rm(path.join(vault, `${missingPayloadItem.id}.bin`));

  const corruptId = crypto.randomUUID();
  await fs.writeFile(path.join(vault, `${corruptId}.json`), '{not valid json');
  const oversizedId = crypto.randomUUID();
  await fs.writeFile(path.join(vault, `${oversizedId}.json`), Buffer.alloc(64 * 1024 + 1, 0x20));

  const inventory = await quarantine.list({ limit: 2 });
  assert.equal(inventory.items.length, 2);
  assert.equal(inventory.total, 3);
  assert.equal(inventory.truncatedCount, 1);
  assert.equal(inventory.corruptCount, 2);
  assert.equal(inventory.oversizedCount, 1);
  assert.ok(inventory.items.every(item => validIds.has(item.id)));

  const byteBounded = await quarantine.list({ maxBytes: 1 });
  assert.equal(byteBounded.items.length, 0);
  assert.equal(byteBounded.total, 3);
  assert.equal(byteBounded.truncatedCount, 3);
});

test('restore rejects oversized or corrupt metadata before creating a destination', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-restore-metadata-limit-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const vault = path.join(root, 'vault');
  const source = path.join(root, 'source.bin');
  const destination = path.join(root, 'restored', 'source.bin');
  const payload = Buffer.from('bounded restore metadata fixture');
  await fs.writeFile(source, payload);
  const quarantine = new Quarantine(vault);
  const item = await quarantine.isolate(source, scanRecord(payload));
  const metadataFile = path.join(vault, `${item.id}.json`);

  await fs.writeFile(metadataFile, Buffer.alloc(64 * 1024 + 1, 0x20));
  await assert.rejects(quarantine.restore(item.id, destination), /size limit/);
  await assert.rejects(fs.access(destination), { code: 'ENOENT' });

  await fs.writeFile(metadataFile, '{invalid json');
  await assert.rejects(quarantine.restore(item.id, destination), SyntaxError);
  await assert.rejects(fs.access(destination), { code: 'ENOENT' });
  assert.equal((await fs.stat(path.join(vault, `${item.id}.bin`))).isFile(), true);
  assert.equal((await fs.readdir(root)).some(name => name.endsWith('.restore-tmp')), false);
});
