import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const POWERSHELL = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const WINDOWS_MODULES = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\Modules`;
const MAX_PROCESSES = 512;
const MAX_PERSISTENCE = 256;
const MAX_EVENTS = 300;
const MAX_INCIDENTS = 100;
const MAX_TEXT = 2_000;
const MAX_PATH = 1_000;

const TECHNIQUES = Object.freeze({
  powershell: ['T1059.001', 'PowerShell'],
  commandShell: ['T1059.003', 'Windows Command Shell'],
  obfuscated: ['T1027', 'Obfuscated Files or Information'],
  regsvr32: ['T1218.010', 'Regsvr32'],
  rundll32: ['T1218.011', 'Rundll32'],
  mshta: ['T1218.005', 'Mshta'],
  startup: ['T1547.001', 'Registry Run Keys / Startup Folder'],
  scheduledTask: ['T1053.005', 'Scheduled Task / Job: Scheduled Task'],
  service: ['T1543.003', 'Windows Service']
});

const SCRIPT = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$processes = @(Get-CimInstance Win32_Process | Select-Object -First __PROCESS_LIMIT__ ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate)
$startup = @(Get-CimInstance Win32_StartupCommand | Select-Object -First __PERSISTENCE_LIMIT__ Name,Command,Location,User)
$runKeys = @()
foreach ($key in @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce')) {
  try { $item = Get-ItemProperty -Path $key -ErrorAction Stop; foreach ($property in $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) { $runKeys += [pscustomobject]@{Name=[string]$property.Name;Command=[string]$property.Value;Location=$key;User=''} } } catch {}
}
$runKeys = @($runKeys | Select-Object -First __PERSISTENCE_LIMIT__)
$tasks = @(Get-ScheduledTask | Select-Object -First __PERSISTENCE_LIMIT__ | ForEach-Object {
  $action = @($_.Actions | Select-Object -First 1)[0]
  [pscustomobject]@{Name=[string]$_.TaskName;Path=[string]$_.TaskPath;State=[string]$_.State;Author=[string]$_.Principal.UserId;Command=[string]$action.Execute;Arguments=[string]$action.Arguments}
})
$services = @(Get-CimInstance Win32_Service | Select-Object -First __PERSISTENCE_LIMIT__ Name,DisplayName,State,StartMode,PathName,StartName)
[pscustomobject]@{Processes=@($processes);Startup=@($startup);RunKeys=@($runKeys);Tasks=@($tasks);Services=@($services)} | ConvertTo-Json -Depth 8 -Compress
`;

export class EDRAuditor {
  constructor({ runner = runPowerShell, maxProcesses = MAX_PROCESSES, maxPersistence = MAX_PERSISTENCE, maxEvents = MAX_EVENTS, now = () => new Date() } = {}) {
    this.runner = runner;
    this.maxProcesses = clampLimit(maxProcesses, MAX_PROCESSES);
    this.maxPersistence = clampLimit(maxPersistence, MAX_PERSISTENCE);
    this.maxEvents = clampLimit(maxEvents, MAX_EVENTS);
    this.now = now;
  }

  async audit({ networkReport = null, history = [], ransomwareAlerts = [] } = {}) {
    const startedAt = this.now().toISOString();
    if (process.platform !== 'win32' && this.runner === runPowerShell) {
      return unavailable(startedAt, 'La auditoría EDR local requiere Windows PowerShell.');
    }
    let raw;
    try {
      raw = await this.runner({ processLimit: this.maxProcesses, persistenceLimit: this.maxPersistence });
    } catch (error) {
      return unavailable(startedAt, `No se pudo tomar la instantánea EDR: ${text(error?.message, 'error de PowerShell')}`);
    }

    const report = buildReport(raw, { startedAt, completedAt: this.now().toISOString(), networkReport, history, ransomwareAlerts, maxProcesses: this.maxProcesses, maxPersistence: this.maxPersistence, maxEvents: this.maxEvents });
    return report;
  }
}

export async function writeEdrReport(directory, report) {
  await fs.mkdir(directory, { recursive: true });
  const stamp = String(report?.completedAt ?? new Date().toISOString()).replace(/[:.]/g, '-');
  const file = path.join(directory, `edr-${stamp}-${crypto.randomUUID()}.json`);
  await fs.writeFile(file, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return { json: file };
}

function buildReport(raw, { startedAt, completedAt, networkReport, history, ransomwareAlerts, maxProcesses, maxPersistence, maxEvents }) {
  const processValues = asArray(raw?.Processes ?? raw?.processes);
  const processes = processValues.slice(0, maxProcesses).map(normalizeProcess).filter(Boolean);
  const processById = new Map(processes.filter(item => item.pid > 0).map(item => [item.pid, item]));
  for (const process of processes) {
    process.children = processes.filter(child => child.parentPid === process.pid).slice(0, 32).map(child => child.pid);
  }
  const processTreeEdges = processes
    .filter(item => item.parentPid > 0 && processById.has(item.parentPid))
    .slice(0, maxProcesses)
    .map(item => ({ parentPid: item.parentPid, childPid: item.pid }));

  const events = [];
  const add = event => { if (events.length < maxEvents) events.push(event); };
  for (const process of processes) {
    const findings = classifyCommand(`${process.name} ${process.path} ${process.commandLine}`);
    add(processEvent(process, findings));
  }

  const persistenceArtifacts = [];
  for (const item of asArray(raw?.Startup ?? raw?.startup).slice(0, maxPersistence)) {
    const artifact = normalizePersistence('startup', item);
    if (artifact) { persistenceArtifacts.push(artifact); add(persistenceEvent(artifact)); }
  }
  for (const item of asArray(raw?.RunKeys ?? raw?.runKeys).slice(0, maxPersistence)) {
    const artifact = normalizePersistence('run-key', item);
    if (artifact) { persistenceArtifacts.push(artifact); add(persistenceEvent(artifact)); }
  }
  for (const item of asArray(raw?.Tasks ?? raw?.tasks).slice(0, maxPersistence)) {
    const artifact = normalizePersistence('scheduled-task', item);
    if (artifact) { persistenceArtifacts.push(artifact); add(persistenceEvent(artifact)); }
  }
  for (const item of asArray(raw?.Services ?? raw?.services).slice(0, maxPersistence)) {
    const artifact = normalizePersistence('service', item);
    if (artifact) { persistenceArtifacts.push(artifact); add(persistenceEvent(artifact)); }
  }

  for (const rawEvent of asArray(networkReport?.events).slice(0, 100)) add(networkEvent(rawEvent, processById));
  for (const alert of asArray(ransomwareAlerts).slice(0, 50)) add(ransomwareEvent(alert));
  for (const item of asArray(history).filter(entry => ['monitor-detection', 'protection-detection'].includes(entry?.type)).slice(0, 50)) add(fileEvent(item));

  const incidents = correlateIncidents(events);
  const suspicious = events.filter(event => event.verdict === 'suspicious').length;
  const truncated = processValues.length > maxProcesses
    || asArray(raw?.Startup ?? raw?.startup).length > maxPersistence
    || asArray(raw?.RunKeys ?? raw?.runKeys).length > maxPersistence
    || asArray(raw?.Tasks ?? raw?.tasks).length > maxPersistence
    || asArray(raw?.Services ?? raw?.services).length > maxPersistence
    || events.length >= maxEvents;

  return {
    schemaVersion: 1,
    mode: 'audit',
    available: true,
    source: 'windows-powershell',
    startedAt,
    completedAt,
    limitations: [
      'Instantánea bajo demanda; no es telemetría ETW continua.',
      'Los eventos de archivos y ransomware no se atribuyen a un proceso sin telemetría nativa.',
      'No se terminan procesos ni se eliminan persistencias automáticamente.'
    ],
    summary: {
      processes: processes.length,
      processTreeEdges: processTreeEdges.length,
      persistenceArtifacts: persistenceArtifacts.length,
      timelineEvents: events.length,
      incidents: incidents.length,
      suspicious,
      truncated
    },
    processes,
    processTreeEdges,
    persistenceArtifacts,
    events,
    incidents,
    response: responsePolicy()
  };
}

function normalizeProcess(value) {
  if (!value || typeof value !== 'object') return null;
  const pid = integer(value.ProcessId ?? value.pid);
  return {
    pid,
    parentPid: integer(value.ParentProcessId ?? value.parentPid),
    name: text(value.Name ?? value.name, 'Proceso desconocido', 260),
    path: text(value.ExecutablePath ?? value.Path ?? value.path, '', MAX_PATH),
    commandLine: text(value.CommandLine ?? value.commandLine, '', MAX_TEXT),
    createdAt: date(value.CreationDate ?? value.createdAt),
    children: []
  };
}

function normalizePersistence(type, value) {
  if (!value || typeof value !== 'object') return null;
  const command = text(value.Command ?? value.command ?? value.PathName, '', MAX_TEXT);
  const argumentsText = text(value.Arguments ?? value.arguments, '', MAX_TEXT);
  const artifactPath = text(value.Location ?? value.Path ?? value.path ?? value.PathName, '', MAX_PATH);
  const label = text(value.Name ?? value.name ?? value.DisplayName, type, 260);
  const findings = classifyCommand(`${label} ${command} ${argumentsText} ${artifactPath}`);
  const userWritable = isUserWritable(`${command} ${argumentsText} ${artifactPath}`);
  const technique = type === 'startup' || type === 'run-key' ? TECHNIQUES.startup : type === 'scheduled-task' ? TECHNIQUES.scheduledTask : TECHNIQUES.service;
  const techniqueIds = unique([technique[0], ...findings.techniqueIds]);
  const techniqueLabels = unique([technique[1], ...findings.techniqueLabels]);
  const suspicious = findings.suspicious || userWritable;
  return {
    type,
    name: label,
    path: artifactPath,
    command: `${command}${argumentsText ? ` ${argumentsText}` : ''}`.trim().slice(0, MAX_TEXT),
    userWritable,
    verdict: suspicious ? 'suspicious' : 'observed',
    techniqueIds,
    techniqueLabels,
    explanation: suspicious
      ? userWritable ? 'Persistencia observada en una ubicación escribible por el usuario; requiere revisión.' : findings.explanation
      : 'Persistencia registrada en la instantánea; no hay indicios suficientes para clasificarla como maliciosa.'
  };
}

function processEvent(process, findings) {
  return makeEvent({
    kind: 'process', severity: findings.suspicious ? 'medium' : 'info', verdict: findings.suspicious ? 'suspicious' : 'observed',
    title: findings.suspicious ? `Proceso con indicios: ${process.name}` : `Proceso observado: ${process.name}`,
    explanation: findings.suspicious ? findings.explanation : 'Proceso presente en la instantánea local; no se ha ejecutado ni modificado.',
    techniqueIds: findings.techniqueIds, techniqueLabels: findings.techniqueLabels,
    process: processAttribution(process, true, 'PID presente en la instantánea EDR.')
  });
}

function persistenceEvent(artifact) {
  return makeEvent({
    kind: 'persistence', severity: artifact.verdict === 'suspicious' ? 'medium' : 'low', verdict: artifact.verdict,
    title: `${artifact.type === 'service' ? 'Servicio' : artifact.type === 'scheduled-task' ? 'Tarea programada' : 'Inicio automático'}: ${artifact.name}`,
    explanation: artifact.explanation, techniqueIds: artifact.techniqueIds, techniqueLabels: artifact.techniqueLabels,
    artifact: { type: artifact.type, path: artifact.path, label: artifact.name }
  });
}

function networkEvent(raw, processById) {
  const suspicious = raw?.verdict === 'suspicious';
  const pid = integer(raw?.process?.id ?? raw?.ProcessId);
  const process = processById.get(pid);
  return makeEvent({
    kind: 'network', severity: suspicious ? 'medium' : 'info', verdict: suspicious ? 'suspicious' : 'observed',
    title: suspicious ? 'Conexión coincidente con un indicador' : 'Conexión saliente observada',
    explanation: text(raw?.explanation, 'Conexión observada por la auditoría de red.', 500), techniqueIds: [], techniqueLabels: [],
    process: process ? processAttribution(process, true, 'PID coincidente con la instantánea EDR.') : processAttribution({ pid, name: text(raw?.process?.name, 'Proceso desconocido', 260), path: text(raw?.process?.path, '', MAX_PATH) }, false, 'El proceso no estaba presente en la instantánea EDR.'),
    artifact: { type: 'network', path: text(raw?.domain || raw?.remoteAddress, 'destino remoto', 253), label: `${text(raw?.domain || raw?.remoteAddress, 'destino remoto', 253)}:${integer(raw?.remotePort)}` }
  });
}

function ransomwareEvent(alert) {
  return makeEvent({
    kind: 'ransomware', severity: ['critical', 'high', 'medium'].includes(alert?.severity) ? alert.severity : 'medium', verdict: 'suspicious',
    title: 'Actividad compatible con ransomware', explanation: text(alert?.explanation, 'Cambio anómalo observado en una carpeta protegida.', 500),
    techniqueIds: [], techniqueLabels: [], process: processAttribution({}, false, 'La atribución por escritura requiere telemetría nativa.'),
    artifact: { type: 'file', path: text(alert?.fileName || alert?.rootLabel, 'carpeta protegida', MAX_PATH), label: text(alert?.rootLabel || alert?.fileName, 'carpeta protegida', 260) }
  });
}

function fileEvent(entry) {
  return makeEvent({
    kind: 'file', severity: entry.verdict === 'malicious' ? 'high' : 'medium', verdict: entry.verdict === 'malicious' || entry.verdict === 'suspicious' ? 'suspicious' : 'observed',
    title: 'Detección de archivo en vigilancia', explanation: 'Resultado de vigilancia incorporado a la línea temporal; el proceso autor no está disponible.',
    techniqueIds: [], techniqueLabels: [], process: processAttribution({}, false, 'La atribución por escritura requiere telemetría nativa.'), artifact: { type: 'file', path: text(entry.path, 'archivo observado', MAX_PATH), label: text(entry.path, 'archivo observado', 260) }
  });
}

function makeEvent({ kind, severity, verdict, title, explanation, techniqueIds, techniqueLabels, process, artifact }) {
  return {
    id: cryptoRandomId(), at: new Date().toISOString(), kind, severity, verdict, title: text(title, 'Evento EDR', 260), explanation: text(explanation, 'Sin explicación adicional.', 500),
    source: 'local-audit', techniqueIds: unique(techniqueIds).slice(0, 8), techniqueLabels: unique(techniqueLabels).slice(0, 8),
    process: process ?? processAttribution({}, false, 'No atribuido'), artifact: artifact ? { type: text(artifact.type, 'artifact', 80), path: text(artifact.path, '', MAX_PATH), label: text(artifact.label, '', 260) } : null,
    action: 'observed-only'
  };
}

function correlateIncidents(events) {
  const groups = new Map();
  for (const event of events.filter(item => item.verdict === 'suspicious')) {
    const key = event.process?.attributed ? `pid:${event.process.pid}` : event.artifact?.path ? `${event.kind}:${event.artifact.path.toLowerCase()}` : `event:${event.id}`;
    const group = groups.get(key) ?? { id: cryptoRandomId(), at: event.at, severity: 'medium', title: event.title, status: 'observed', eventIds: [], techniqueIds: [], techniqueLabels: [], process: event.process, response: responsePolicy() };
    group.eventIds.push(event.id); group.techniqueIds.push(...event.techniqueIds); group.techniqueLabels.push(...event.techniqueLabels);
    if (event.severity === 'high' || event.severity === 'critical') group.severity = event.severity;
    groups.set(key, group);
  }
  return [...groups.values()].slice(0, MAX_INCIDENTS).map(group => ({ ...group, eventCount: group.eventIds.length, techniqueIds: unique(group.techniqueIds).slice(0, 8), techniqueLabels: unique(group.techniqueLabels).slice(0, 8) }));
}

function classifyCommand(value) {
  const command = String(value ?? '').toLowerCase();
  const ids = []; const labels = []; const reasons = [];
  const add = (key, reason) => { ids.push(TECHNIQUES[key][0]); labels.push(TECHNIQUES[key][1]); reasons.push(reason); };
  if (/(?:^|[\\/])(?:powershell|pwsh)(?:\.exe)?\b/.test(command)) add('powershell', 'Usa PowerShell, que requiere revisión contextual.');
  if (/(?:cmd(?:\.exe)?\s+\/c|command\.com\s+\/c)/.test(command)) add('commandShell', 'Ejecuta un intérprete de comandos mediante /c.');
  if (/(?:-enc(?:odedcommand)?\b|frombase64string|invoke-expression|iex\s|\-nop\b)/.test(command)) add('obfuscated', 'Contiene indicadores de ofuscación o ejecución dinámica.');
  if (/(?:regsvr32(?:\.exe)?\b)/.test(command)) add('regsvr32', 'Invoca Regsvr32, una utilidad que puede cargar contenido indirectamente.');
  if (/(?:rundll32(?:\.exe)?\b)/.test(command)) add('rundll32', 'Invoca Rundll32 para cargar una DLL.');
  if (/(?:mshta(?:\.exe)?\b)/.test(command)) add('mshta', 'Invoca Mshta, un binario de confianza de alto riesgo contextual.');
  return { suspicious: ids.length > 0, techniqueIds: unique(ids), techniqueLabels: unique(labels), explanation: reasons.join(' ') || 'No se encontraron patrones de ejecución de alto riesgo en esta instantánea.' };
}

function isUserWritable(value) {
  return /(?:\\|\/)users(?:\\|\/)[^\\/]+(?:\\|\/)(?:appdata|downloads|desktop|documents|temp)|(?:\\|\/)(?:windows\\temp|temp)(?:\\|\/)/i.test(String(value ?? ''));
}

function processAttribution(process, attributed, reason) {
  return { attributed, pid: integer(process?.pid), name: text(process?.name, attributed ? 'Proceso desconocido' : '', 260), path: text(process?.path, '', MAX_PATH), parentPid: integer(process?.parentPid), reason: text(reason, 'Sin atribución', 260) };
}

function responsePolicy() {
  return { mode: 'audit', blocking: false, terminationAvailable: false, removalAvailable: false, quarantineAvailable: false };
}

function unavailable(at, error) {
  return { schemaVersion: 1, mode: 'audit', available: false, source: 'unavailable', startedAt: at, completedAt: at, limitations: ['La auditoría EDR local no está disponible en este entorno.'], summary: { processes: 0, processTreeEdges: 0, persistenceArtifacts: 0, timelineEvents: 0, incidents: 0, suspicious: 0, truncated: false }, processes: [], processTreeEdges: [], persistenceArtifacts: [], events: [], incidents: [], response: responsePolicy(), error: text(error, 'Auditoría no disponible', 500) };
}

function runPowerShell({ processLimit, persistenceLimit }) {
  return new Promise((resolve, reject) => {
    const script = SCRIPT.replace('__PROCESS_LIMIT__', String(processLimit)).replaceAll('__PERSISTENCE_LIMIT__', String(persistenceLimit));
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    execFile(POWERSHELL, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
      windowsHide: true,
      timeout: 30_000,
      maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env, PSModulePath: [WINDOWS_MODULES, process.env.PSModulePath].filter(Boolean).join(';') }
    }, (error, stdout) => {
      if (error) return reject(error);
      try { resolve(JSON.parse(stdout.trim())); } catch (parseError) { reject(parseError); }
    });
  });
}

function clampLimit(value, maximum) { return Math.max(1, Math.min(maximum, Number.isSafeInteger(value) ? value : maximum)); }
function asArray(value) { return Array.isArray(value) ? value : value == null ? [] : [value]; }
function integer(value) { const number = Number(value); return Number.isSafeInteger(number) && number >= 0 ? number : 0; }
function text(value, fallback = '', maximum = MAX_TEXT) { const result = typeof value === 'string' && value.trim() ? value.trim() : fallback; return String(result).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maximum); }
function date(value) { if (!value) return null; const parsed = new Date(value); return Number.isNaN(parsed.valueOf()) ? null : parsed.toISOString(); }
function unique(values) { return [...new Set(asArray(values).filter(item => typeof item === 'string' && item))]; }
function cryptoRandomId() { return crypto.randomUUID(); }
