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
