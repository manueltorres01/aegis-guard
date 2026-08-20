import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanEngine } from '../src/engine.mjs';
import { Quarantine } from '../src/quarantine.mjs';
import { createHarmlessSimulation } from '../src/simulator.mjs';
import definitions from '../definitions/signatures.json' with { type: 'json' };

const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

test('detects EICAR and can quarantine and restore it safely', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = path.join(dir, 'eicar.com');
  await fs.writeFile(sample, eicar);
  const engine = new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'malicious');
  assert.equal(result.score, 100);
  const quarantine = new Quarantine(path.join(dir, 'vault'));
  const metadata = await quarantine.isolate(sample, result);
  await assert.rejects(fs.access(sample));
  const restored = path.join(dir, 'restored.com');
  await quarantine.restore(metadata.id, restored);
  assert.equal(await fs.readFile(restored, 'utf8'), eicar);
});

test('does not flag ordinary text', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = path.join(dir, 'notes.txt');
  await fs.writeFile(sample, 'Quarterly planning notes and harmless content.');
  const engine = new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'clean');
});

test('detects the harmless simulator and quarantines instead of deleting', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = await createHarmlessSimulation(dir);
  const engine = new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'malicious');
  assert.ok(result.findings.some(x => x.id === 'test.aegis-simulation'));
  const quarantine = new Quarantine(path.join(dir, 'vault'));
  await quarantine.isolate(sample, result);
  await assert.rejects(fs.access(sample));
  assert.equal((await quarantine.list()).items.length, 1);
});

test('does not detect the encoded definitions file as malware', async () => {
  const engine = new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
  const result = await engine.scanFile(fileURLToPath(new URL('../definitions/signatures.json', import.meta.url)));
  assert.equal(result.verdict, 'clean');
});

test('does not treat a single process API name in a DLL as an injection combination', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = path.join(dir, 'legitimate-component.dll');
  await fs.writeFile(sample, Buffer.concat([Buffer.from('MZ WriteProcessMemory ordinary import data '), Buffer.alloc(8192, 65)]));
  const engine = new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'clean');
  assert.equal(result.findings.some(x => x.id === 'heuristic.pe-api-combination'), false);
});

test('requires a real group of process-injection API references in a binary', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = path.join(dir, 'injector.dll');
  await fs.writeFile(sample, Buffer.concat([Buffer.from('MZ CreateRemoteThread VirtualAllocEx WriteProcessMemory '), Buffer.alloc(8192, 65)]));
  const engine = new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'suspicious');
  assert.ok(result.findings.some(x => x.id === 'heuristic.pe-api-combination'));
});

test('keeps script-only execution rules out of ordinary PE string tables', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = path.join(dir, 'script-host.dll');
  await fs.writeFile(sample, Buffer.concat([Buffer.from('MZ FromBase64String Invoke-Expression help text'), Buffer.alloc(8192, 65)]));
  const engine = new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'clean');
  assert.equal(result.findings.some(x => x.id === 'heuristic.script'), false);
});

test('records valid trusted signatures and neutralizes only low-confidence binary heuristics', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = path.join(dir, 'signed-driver.dll');
  await fs.writeFile(sample, Buffer.concat([Buffer.from('MZ CreateRemoteThread VirtualAllocEx WriteProcessMemory '), Buffer.alloc(8192, 65)]));
  const engine = new ScanEngine({
    definitions, threshold: 60, maxFileSizeMb: 1,
    trustedPublisherOrganizations: ['Microsoft Corporation'],
    trustVerifier: async () => ({ status: 'valid', subject: 'CN=Microsoft Windows, O=Microsoft Corporation', organization: 'Microsoft Corporation', companyName:'Microsoft Corporation',productName:'Windows Component',fileVersion:'10.0.1',zoneId:3 })
  });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'clean');
  assert.equal(result.score, 0);
  assert.equal(result.trust.organization, 'Microsoft Corporation');
  assert.equal(result.trust.companyName, 'Microsoft Corporation');
  assert.equal(result.trust.productName, 'Windows Component');
  assert.equal(result.trust.fileVersion, '10.0.1');
  assert.equal(result.trust.zoneId, 3);
  assert.ok(result.findings.some(x => x.id === 'trust.authenticode'));
});

test('does not trust a valid signature from an unlisted publisher', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const sample = path.join(dir, 'signed-unknown.dll');
  await fs.writeFile(sample, Buffer.concat([Buffer.from('MZ CreateRemoteThread VirtualAllocEx WriteProcessMemory '), Buffer.alloc(8192, 65)]));
  const engine = new ScanEngine({
    definitions, threshold: 60, maxFileSizeMb: 1,
    trustedPublisherOrganizations: ['Microsoft Corporation'],
    trustVerifier: async () => ({ status: 'valid', subject: 'CN=Unknown Vendor', organization: 'Unknown Vendor' })
  });
  const result = await engine.scanFile(sample);
  assert.equal(result.verdict, 'suspicious');
  assert.equal(result.score, 28);
});

test('verified application trust requires both the expected publisher and installation root', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-app-policy-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const installed = path.join(dir, 'Discord', 'app-1', 'Discord.exe');
  const copied = path.join(dir, 'Elsewhere', 'Discord.exe');
  await fs.mkdir(path.dirname(installed), { recursive: true });
  await fs.mkdir(path.dirname(copied), { recursive: true });
  const content = Buffer.concat([Buffer.from('MZ CreateRemoteThread VirtualAllocEx WriteProcessMemory '), Buffer.alloc(8192, 65)]);
  await Promise.all([fs.writeFile(installed, content), fs.writeFile(copied, content)]);
  const engine = new ScanEngine({
    definitions, threshold: 60, maxFileSizeMb: 1,
    trustedApplicationPolicies: [{ publisher: 'Discord Inc.', roots: [path.join(dir, 'Discord')] }],
    trustVerifier: async () => ({ status: 'valid', subject: 'CN=Discord Inc., O=Discord Inc.', organization: 'Discord Inc.' })
  });
  const trusted = await engine.scanFile(installed);
  const outside = await engine.scanFile(copied);
  assert.equal(trusted.verdict, 'clean');
  assert.equal(trusted.trust.applicationVerified, true);
  assert.equal(outside.verdict, 'suspicious');
  assert.equal(outside.trust.applicationVerified, false);
});
