import test from 'node:test';
import assert from 'node:assert/strict';
import { EDRAuditor, writeEdrReport } from '../src/edr-audit.mjs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

test('EDR audit builds bounded process trees and explains suspicious commands', async () => {
  const auditor = new EDRAuditor({
    maxProcesses: 3,
    maxPersistence: 4,
    runner: async () => ({
      Processes: [
        { ProcessId: 10, ParentProcessId: 0, Name: 'explorer.exe', ExecutablePath: 'C:\\Windows\\explorer.exe', CommandLine: 'explorer.exe' },
        { ProcessId: 20, ParentProcessId: 10, Name: 'powershell.exe', ExecutablePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -EncodedCommand SGVsbG8=' },
        { ProcessId: 30, ParentProcessId: 20, Name: 'rundll32.exe', ExecutablePath: 'C:\\Windows\\System32\\rundll32.exe', CommandLine: 'rundll32.exe C:\\Users\\demo\\AppData\\Local\\x.dll,Entry' },
        { ProcessId: 40, ParentProcessId: 0, Name: 'ignored.exe', ExecutablePath: 'C:\\ignored.exe' }
      ],
      Startup: [{ Name: 'Demo', Command: 'powershell.exe -enc AAA=', Location: 'HKCU\\Run', User: 'demo' }],
      RunKeys: [{ Name: 'Updater', Command: 'C:\\Users\\demo\\AppData\\Roaming\\updater.exe', Location: 'HKCU Run' }],
      Tasks: [{ Name: 'Demo task', Path: '\\\\', Command: 'C:\\Windows\\System32\\cmd.exe', Arguments: '/c whoami' }],
      Services: [{ Name: 'DemoSvc', PathName: 'C:\\Users\\demo\\AppData\\Local\\demo.exe' }]
    }),
    now: () => new Date('2026-08-20T12:00:00.000Z')
  });
  const report = await auditor.audit();
  assert.equal(report.available, true);
  assert.equal(report.processes.length, 3);
  assert.equal(report.summary.truncated, true);
  assert.equal(report.processTreeEdges.length, report.summary.processTreeEdges);
  assert.ok(report.events.some(event => event.techniqueIds.includes('T1059.001')));
  assert.ok(report.events.some(event => event.techniqueIds.includes('T1027')));
  assert.ok(report.persistenceArtifacts.some(item => item.userWritable && item.verdict === 'suspicious'));
  assert.ok(report.incidents.length >= 1);
  assert.equal(report.response.terminationAvailable, false);
  assert.equal(report.response.removalAvailable, false);
});

test('EDR audit correlates network and file history without inventing process attribution', async () => {
  const report = await new EDRAuditor({
    runner: async () => ({ Processes: [{ ProcessId: 42, ParentProcessId: 1, Name: 'demo.exe', ExecutablePath: 'C:\\Program Files\\Demo\\demo.exe' }] }),
    now: () => new Date('2026-08-20T12:00:00.000Z')
  }).audit({
    networkReport: { events: [{ verdict: 'suspicious', explanation: 'Indicador local', process: { id: 42, name: 'demo.exe', path: 'C:\\Program Files\\Demo\\demo.exe' }, domain: 'bad.example' }] },
    ransomwareAlerts: [{ severity: 'high', explanation: 'Muchos cambios', rootLabel: 'Documentos', fileName: 'x.docx' }],
    history: [{ type: 'monitor-detection', verdict: 'suspicious', path: 'C:\\Users\\demo\\Downloads\\x.exe' }]
  });
  assert.ok(report.events.some(event => event.kind === 'network' && event.process.attributed));
  assert.ok(report.events.some(event => event.kind === 'ransomware' && !event.process.attributed));
  assert.ok(report.events.some(event => event.kind === 'file' && !event.process.attributed));
  assert.ok(report.incidents.length >= 2);
  assert.ok(report.events.every(event => event.action === 'observed-only'));
});

test('EDR report writer keeps a bounded JSON report', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-edr-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const files = await writeEdrReport(directory, { completedAt: '2026-08-20T12:00:00.000Z', summary: { timelineEvents: 1 }, events: [] });
  assert.equal(JSON.parse(await fs.readFile(files.json, 'utf8')).summary.timelineEvents, 1);
});
