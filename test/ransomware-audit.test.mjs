import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { RansomwareAudit } from '../src/ransomware-audit.mjs';

function harness(root, overrides = {}) {
  let callback;
  const watcher = new EventEmitter();
  watcher.close = () => { watcher.closed = true; };
  const alerts = [];
  const audit = new RansomwareAudit({
    roots: [root],
    watcherFactory: (_root, _options, handler) => { callback = handler; return watcher; },
    emit: event => alerts.push(event),
    changeThreshold: 5,
    deleteThreshold: 3,
    extensionThreshold: 3,
    alertCooldownMs: 1_000,
    ...overrides
  });
  return { audit, alerts, watcher, event: (...args) => callback(...args) };
}

const settle = () => new Promise(resolve => setTimeout(resolve, 20));

test('ransomware audit creates a bounded canary and reports tampering without blocking', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-ransomware-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const subject = harness(root);
  const status = await subject.audit.start();
  assert.equal(status.mode, 'audit');
  assert.equal(status.blocking, false);
  assert.equal(status.processAttribution, 'unavailable');
  const canary = (await fs.readdir(root)).find(name => name.startsWith('_AegisGuard_Canary_'));
  assert.ok(canary);
  await fs.rm(path.join(root, canary));
  subject.event('rename', canary);
  await settle();
  assert.equal(subject.alerts[0].type, 'ransomware-audit-alert');
  assert.equal(subject.alerts[0].payload.kind, 'canary-tamper');
  assert.equal(subject.alerts[0].payload.action, 'observed-only');
  await subject.audit.stop();
  assert.equal(subject.watcher.closed, true);
  await subject.audit.stop({ removeCanaries: true });
});

test('ransomware audit correlates rapid appended-extension renames', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-ransomware-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse('2026-08-20T10:00:00.000Z');
  const subject = harness(root, { clock: () => now });
  await subject.audit.start();
  for (let index = 0; index < 3; index++) {
    const original = `document-${index}.docx`;
    const encrypted = `${original}.locked`;
    subject.event('rename', original);
    await settle();
    await fs.writeFile(path.join(root, encrypted), 'encrypted-looking test data');
    now += 150;
    subject.event('rename', encrypted);
    await settle();
    now += 150;
  }
  const alert = subject.alerts.find(event => event.payload.kind === 'mass-extension-change');
  assert.ok(alert);
  assert.equal(alert.payload.counts.extensionChanges, 3);
  assert.equal(alert.payload.process.attributed, false);
  await subject.audit.stop({ removeCanaries: true });
});

test('ransomware audit detects many distinct changes and bounds repeated alerts', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-ransomware-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse('2026-08-20T10:00:00.000Z');
  const subject = harness(root, { clock: () => now });
  await subject.audit.start();
  for (let index = 0; index < 8; index++) {
    const name = `changed-${index}.txt`;
    await fs.writeFile(path.join(root, name), String(index));
    subject.event('change', name);
    await settle();
    now += 120;
  }
  assert.equal(subject.alerts.filter(event => event.payload.kind === 'high-rate-file-change').length, 1);
  assert.ok(subject.audit.status().recentAlerts.length <= 20);
  await subject.audit.stop({ removeCanaries: true });
});

