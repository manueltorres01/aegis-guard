import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ExposureAuditor, writeExposureReport } from '../src/exposure-audit.mjs';

test('exposure audit inventories removable media, applications and unsafe settings', async t => {
  const auditor = new ExposureAuditor({
    runner: async () => ({
      Devices: [{ DeviceID: 'E:', VolumeName: 'USB de prueba', FileSystem: 'exFAT', Size: 1000, FreeSpace: 400 }],
      Applications: [
        { DisplayName: 'Discord', Publisher: 'Discord Inc.', DisplayVersion: '1.0', InstallLocation: 'C:\\Discord' },
        { DisplayName: 'Legacy Tool', Publisher: '', DisplayVersion: '', InstallLocation: '' }
      ],
      Firewall: [{ Name: 'Public', Enabled: false }],
      Defender: { AntivirusEnabled: true, RealTimeProtectionEnabled: false },
      Uac: { EnableLUA: 0, ConsentPromptBehaviorAdmin: 5, PromptOnSecureDesktop: 1 },
      SecureBoot: false,
      Privacy: [{ Capability: 'webcam', App: '(global)', Decision: 'Allow' }]
    }),
    now: () => new Date('2026-08-20T10:00:00.000Z'),
    policies: { publishers: ['Discord'], exceptions: [{ name: 'Legacy Tool', expiresAt: '2026-08-19T00:00:00.000Z', reason: 'Temporal' }] }
  });
  const report = await auditor.audit();
  assert.equal(report.summary.removableDevices, 1);
  assert.equal(report.summary.applications, 2);
  assert.equal(report.summary.unsafeSettings, 4);
  assert.equal(report.summary.expiredExceptions, 1);
  assert.equal(report.applications[0].policy.status, 'publisher-allowed');
  assert.equal(report.applications[1].policy.status, 'expired-exception');
  assert.equal(report.privacy[0].decision, 'allowed');

  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-exposure-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const files = await writeExposureReport(directory, report);
  assert.equal(JSON.parse(await fs.readFile(files.json, 'utf8')).summary.applications, 2);
  assert.match(await fs.readFile(files.csv, 'utf8'), /removable-device/);
});

test('exposure audit remains available as a bounded audit-only report', async () => {
  const report = await new ExposureAuditor({ runner: async () => ({ Devices: [], Applications: [], Privacy: [] }) }).audit();
  assert.equal(report.mode, 'audit');
  assert.equal(report.policies.enforcementAvailable, false);
  assert.equal(report.policies.blocking, false);
});
