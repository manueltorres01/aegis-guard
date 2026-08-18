import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TARGET_TTL_MS, TargetVault } from '../desktop/target-vault.mjs';

const mainFile = fileURLToPath(new URL('../desktop/main.mjs', import.meta.url));

test('target IDs are one-shot and revalidated when consumed', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-target-vault-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'selected.bin');
  await fs.writeFile(file, 'first identity');
  const vault = new TargetVault();

  const selected = await vault.add(file, 'file');
  const consumed = await vault.consume(selected.id);
  assert.equal(consumed.path, await fs.realpath(file));
  await assert.rejects(vault.consume(selected.id), error => error?.code === 'TARGET_EXPIRED');

  const changed = await vault.add(file, 'file');
  await fs.writeFile(file, 'a different identity and size');
  await assert.rejects(vault.consume(changed.id), error => error?.code === 'TARGET_CHANGED');
  await assert.rejects(vault.consume(changed.id), error => error?.code === 'TARGET_EXPIRED');
});

test('target IDs expire after their ten-minute TTL', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-target-expiry-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const directory = path.join(root, 'selected');
  await fs.mkdir(directory);
  let now = 1_000;
  const vault = new TargetVault({ now: () => now });
  const selected = await vault.add(directory, 'directory');
  now += TARGET_TTL_MS + 1;
  await assert.rejects(vault.consume(selected.id), error => error?.code === 'TARGET_EXPIRED');
});

test('desktop Deep scans and manual monitoring consume target identifiers', async () => {
  const source = await fs.readFile(mainFile, 'utf8');
  const scanStart = source.indexOf('registerHandler(IPC_CHANNELS.startScan');
  const scanEnd = source.indexOf('registerHandler(IPC_CHANNELS.cancelScan', scanStart);
  const scanBlock = source.slice(scanStart, scanEnd);
  assert.notEqual(scanStart, -1, 'startScan handler is missing');
  assert.match(scanBlock, /await targetVault\.consume\(request\.targetId\)/);

  const monitorStart = source.indexOf('registerHandler(IPC_CHANNELS.startMonitor');
  const monitorEnd = source.indexOf('registerHandler(IPC_CHANNELS.stopMonitor', monitorStart);
  const monitorBlock = source.slice(monitorStart, monitorEnd);
  assert.notEqual(monitorStart, -1, 'startMonitor handler is missing');
  assert.match(monitorBlock, /await targetVault\.consume\(request\.targetId\)/);
});
