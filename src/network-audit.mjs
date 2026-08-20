import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const POWERSHELL = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const WINDOWS_MODULES = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\Modules`;
const MAX_EVENTS = 500;
const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$connections = @(Get-NetTCPConnection -State Established,SynSent -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') } | Select-Object -First __MAX_EVENTS__)
$dns = @{}
Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object { if ($_.Data -and $_.Entry) { $dns[[string]$_.Data] = [string]$_.Entry } }
$processes = @{}
$events = foreach ($connection in $connections) {
  $pidValue = [int]$connection.OwningProcess
  if (-not $processes.ContainsKey($pidValue)) {
    $name=''; $processPath=''; $signatureStatus='unavailable'; $publisher=''
    try {
      $process = Get-Process -Id $pidValue -ErrorAction Stop; $name=[string]$process.ProcessName; $processPath=[string]$process.Path
      if ($processPath) { $signature=Get-AuthenticodeSignature -LiteralPath $processPath -ErrorAction SilentlyContinue; if ($signature) { $signatureStatus=[string]$signature.Status; $subject=if ($signature.SignerCertificate) {[string]$signature.SignerCertificate.Subject}else{''}; $publisher=if ($subject -match '(?:^|,\s*)O=([^,]+)') {$Matches[1].Trim()}else{''} } }
    } catch {}
    $processes[$pidValue]=[pscustomobject]@{Name=$name;Path=$processPath;SignatureStatus=$signatureStatus;Publisher=$publisher}
  }
  $identity=$processes[$pidValue]
  [pscustomobject]@{Protocol='tcp';State=[string]$connection.State;LocalAddress=[string]$connection.LocalAddress;LocalPort=[int]$connection.LocalPort;RemoteAddress=[string]$connection.RemoteAddress;RemotePort=[int]$connection.RemotePort;Domain=[string]$dns[[string]$connection.RemoteAddress];ProcessId=$pidValue;ProcessName=$identity.Name;ProcessPath=$identity.Path;SignatureStatus=$identity.SignatureStatus;Publisher=$identity.Publisher}
}
$firewall=@(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {[pscustomobject]@{Name=[string]$_.Name;Enabled=[bool]$_.Enabled;DefaultInboundAction=[string]$_.DefaultInboundAction;DefaultOutboundAction=[string]$_.DefaultOutboundAction}})
$defender=$null
try {$status=Get-MpComputerStatus -ErrorAction Stop; $defender=[pscustomobject]@{AntivirusEnabled=[bool]$status.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$status.RealTimeProtectionEnabled;BehaviorMonitorEnabled=[bool]$status.BehaviorMonitorEnabled;IoavProtectionEnabled=[bool]$status.IoavProtectionEnabled;AntispywareEnabled=[bool]$status.AntispywareEnabled;NISEnabled=[bool]$status.NISEnabled}} catch {}
[pscustomobject]@{Events=@($events);Firewall=@($firewall);Defender=$defender}|ConvertTo-Json -Depth 6 -Compress
`;

export class NetworkAuditor {
  constructor({ indicators = {}, runner = runPowerShell, maxEvents = MAX_EVENTS, now = () => new Date() } = {}) {
    this.indicators = normalizeIndicators(indicators);
    this.runner = runner;
    this.maxEvents = Math.min(MAX_EVENTS, Math.max(1, Number(maxEvents) || MAX_EVENTS));
    this.now = now;
  }
  async audit() {
    const startedAt = this.now().toISOString();
    if (process.platform !== 'win32' && this.runner === runPowerShell) return unavailable(startedAt, 'La auditoría de red solo está disponible en Windows.');
    const raw = await this.runner(this.maxEvents);
    const allEvents = asArray(raw?.Events);
    const events = allEvents.slice(0, this.maxEvents).map(event => explainEvent(event, this.indicators));
    return {
      schemaVersion: 1, mode: 'audit', startedAt, completedAt: this.now().toISOString(),
      summary: { connections: events.length, suspicious: events.filter(x => x.verdict === 'suspicious').length, unsignedProcesses: events.filter(x => x.signature.status !== 'valid').length, truncated: allEvents.length > this.maxEvents },
      windowsSecurity: normalizeSecurity(raw), events
    };
  }
}

export async function writeNetworkReport(directory, report) {
  await fs.mkdir(directory, { recursive: true });
  const stem = `network-${String(report.completedAt).replace(/[:.]/g, '-')}`;
  const json = path.join(directory, `${stem}.json`);
  const csv = path.join(directory, `${stem}.csv`);
  await fs.writeFile(json, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  const rows = [['timestamp','verdict','reason','protocol','remoteAddress','remotePort','domain','processId','processName','processPath','signatureStatus','publisher']];
  for (const event of report.events) rows.push([report.completedAt,event.verdict,event.explanation,event.protocol,event.remoteAddress,event.remotePort,event.domain,event.process.id,event.process.name,event.process.path,event.signature.status,event.signature.publisher]);
  await fs.writeFile(csv, `${rows.map(row => row.map(csvCell).join(',')).join('\r\n')}\r\n`, { flag: 'wx', mode: 0o600 });
  return { json, csv };
}

function explainEvent(raw, indicators) {
  const remoteAddress = text(raw?.RemoteAddress);
  const domain = text(raw?.Domain).replace(/\.$/, '').toLowerCase();
  const ipMatch = indicators.ips.has(remoteAddress);
  const domainMatch = matchesDomain(domain, indicators.domains);
  return {
    verdict: ipMatch || domainMatch ? 'suspicious' : 'observed',
    explanation: ipMatch ? 'La dirección IP coincide con un indicador local configurado.' : domainMatch ? 'El dominio coincide con un indicador local configurado.' : 'Conexión saliente observada; no coincide con los indicadores locales disponibles.',
    protocol: text(raw?.Protocol, 'tcp').toLowerCase(), state: text(raw?.State), localAddress: text(raw?.LocalAddress), localPort: port(raw?.LocalPort), remoteAddress, remotePort: port(raw?.RemotePort), domain,
    process: { id: integer(raw?.ProcessId), name: text(raw?.ProcessName, 'Proceso desconocido'), path: text(raw?.ProcessPath) },
    signature: { status: text(raw?.SignatureStatus).toLowerCase() === 'valid' ? 'valid' : 'unverified', publisher: text(raw?.Publisher) },
    indicators: [...(ipMatch ? [`ip:${remoteAddress}`] : []), ...(domainMatch ? [`domain:${domainMatch}`] : [])]
  };
}
function normalizeSecurity(raw) {
  return { firewall: asArray(raw?.Firewall).map(x => ({ name:text(x?.Name),enabled:x?.Enabled===true,defaultInboundAction:text(x?.DefaultInboundAction),defaultOutboundAction:text(x?.DefaultOutboundAction) })), defender: raw?.Defender ? { antivirusEnabled:raw.Defender.AntivirusEnabled===true,realTimeProtectionEnabled:raw.Defender.RealTimeProtectionEnabled===true,behaviorMonitorEnabled:raw.Defender.BehaviorMonitorEnabled===true,ioavProtectionEnabled:raw.Defender.IoavProtectionEnabled===true,antispywareEnabled:raw.Defender.AntispywareEnabled===true,networkInspectionEnabled:raw.Defender.NISEnabled===true } : null };
}
function normalizeIndicators(value) { return { ips:new Set(asArray(value?.ips).map(text).filter(Boolean)), domains:new Set(asArray(value?.domains).map(x=>text(x).replace(/^\*\./,'').replace(/\.$/,'').toLowerCase()).filter(Boolean)) }; }
function matchesDomain(domain, indicators) { if (!domain) return ''; for (const item of indicators) if (domain === item || domain.endsWith(`.${item}`)) return item; return ''; }
function runPowerShell(maxEvents) { return new Promise((resolve,reject)=>{ const encoded=Buffer.from(SCRIPT.replace('__MAX_EVENTS__',String(maxEvents)),'utf16le').toString('base64'); execFile(POWERSHELL,['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded],{windowsHide:true,timeout:30000,maxBuffer:4*1024*1024,env:{...process.env,PSModulePath:[WINDOWS_MODULES,process.env.PSModulePath].filter(Boolean).join(';')}},(error,stdout)=>{if(error)return reject(error);try{resolve(JSON.parse(stdout.trim()));}catch(parseError){reject(parseError);}});}); }
function unavailable(at,error) { return {schemaVersion:1,mode:'audit',startedAt:at,completedAt:at,error,summary:{connections:0,suspicious:0,unsignedProcesses:0,truncated:false},windowsSecurity:{firewall:[],defender:null},events:[]}; }
function csvCell(value) { let output=String(value??'').replace(/\r?\n/g,' '); if(/^[=+\-@]/.test(output))output=`'${output}`; return `"${output.replace(/"/g,'""')}"`; }
function asArray(value) { return Array.isArray(value)?value:value==null?[]:[value]; }
function text(value,fallback='') { return typeof value==='string'&&value.trim()?value.trim().slice(0,32767):fallback; }
function integer(value) { const number=Number(value); return Number.isSafeInteger(number)&&number>=0?number:0; }
function port(value) { const number=integer(value); return number<=65535?number:0; }
