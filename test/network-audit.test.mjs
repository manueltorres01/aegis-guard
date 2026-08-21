import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { NetworkAuditor, writeNetworkReport } from '../src/network-audit.mjs';

test('network audit attributes destinations and explains indicator matches', async () => {
  const auditor = new NetworkAuditor({ indicators:{domains:['bad.example']}, runner:async()=>({Events:[{RemoteAddress:'203.0.113.9',RemotePort:443,Domain:'api.bad.example',ProcessId:42,ProcessName:'demo',ProcessPath:'C:\\demo.exe',SignatureStatus:'Valid',Publisher:'Demo Corp'},{RemoteAddress:'198.51.100.8',RemotePort:80,ProcessId:7,ProcessName:'other',SignatureStatus:'NotSigned'}],Firewall:[{Name:'Domain',Enabled:true,DefaultInboundAction:'Block',DefaultOutboundAction:'Allow'}],Defender:{AntivirusEnabled:true,RealTimeProtectionEnabled:true,BehaviorMonitorEnabled:true,IoavProtectionEnabled:true,AntispywareEnabled:true,NISEnabled:true}}),now:()=>new Date('2026-08-20T10:00:00.000Z') });
  const report=await auditor.audit();
  assert.equal(report.summary.connections,2); assert.equal(report.summary.suspicious,1);
  assert.equal(report.events[0].process.name,'demo'); assert.equal(report.events[0].signature.publisher,'Demo Corp');
  assert.match(report.events[0].explanation,/dominio/i); assert.equal(report.windowsSecurity.firewall[0].enabled,true);
  assert.equal(report.windowsSecurity.defender.realTimeProtectionEnabled,true);
});

test('network reports export JSON and spreadsheet-safe CSV', async t => {
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'aegis-network-')); t.after(()=>fs.rm(directory,{recursive:true,force:true}));
  const report={completedAt:'2026-08-20T10:00:00.000Z',summary:{},windowsSecurity:{},events:[{verdict:'observed',explanation:'=formula',protocol:'tcp',remoteAddress:'1.1.1.1',remotePort:443,domain:'',process:{id:1,name:'+demo',path:''},signature:{status:'valid',publisher:''}}]};
  const files=await writeNetworkReport(directory,report);
  assert.equal(JSON.parse(await fs.readFile(files.json,'utf8')).events.length,1);
  const csv=await fs.readFile(files.csv,'utf8'); assert.match(csv,/"'=formula"/); assert.match(csv,/"'\+demo"/);
});

test('network audit reports bounded anomalous patterns without claiming maliciousness', async () => {
  const repeated = Array.from({ length: 20 }, () => ({ RemoteAddress: '198.51.100.10', RemotePort: 443, ProcessId: 42, ProcessName: 'sync.exe', BytesSent: 3 * 1024 * 1024 }));
  const ports = Array.from({ length: 12 }, (_, index) => ({ RemoteAddress: '203.0.113.20', RemotePort: 1000 + index, ProcessId: 99, ProcessName: 'tool.exe' }));
  const report = await new NetworkAuditor({ runner: async () => ({ Events: [...repeated, ...ports] }), now: () => new Date('2026-08-20T10:00:00.000Z') }).audit();
  assert.equal(report.summary.connections, 32);
  assert.equal(report.summary.repeatedDestinations, 20);
  assert.equal(report.summary.portScanPatterns, 12);
  assert.equal(report.summary.probableExfiltration, 20);
  assert.ok(report.events.some(event => event.anomalies.includes('repeated-destination')));
  assert.ok(report.events.some(event => event.anomalies.includes('port-scan-pattern')));
  assert.ok(report.events.every(event => event.verdict === 'observed'));
});
