import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const POWERSHELL = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const WINDOWS_MODULES = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\Modules`;
const MAX_DEVICES = 64;
const MAX_APPLICATIONS = 1_000;
const MAX_PRIVACY_ENTRIES = 256;
const MAX_POLICIES = 256;
const MAX_TEXT = 2_000;
const MAX_PATH = 1_000;
const SCRIPT = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$devices = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | Select-Object -First __DEVICE_LIMIT__ DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType,ProviderName)
$apps = @()
foreach ($pattern in @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')) {
  $apps += @(Get-ItemProperty -Path $pattern | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object {
    [pscustomobject]@{DisplayName=[string]$_.DisplayName;DisplayVersion=[string]$_.DisplayVersion;Publisher=[string]$_.Publisher;InstallDate=[string]$_.InstallDate;InstallLocation=[string]$_.InstallLocation;UninstallString=[string]$_.UninstallString;EstimatedSize=[int64]$_.EstimatedSize;WindowsInstaller=[bool]$_.WindowsInstaller}
  })
}
$apps = @($apps | Sort-Object DisplayName,Publisher,DisplayVersion -Unique | Select-Object -First __APPLICATION_LIMIT__)
$firewall = @(Get-NetFirewallProfile | Select-Object -First 8 Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
$defender = $null
try { $status = Get-MpComputerStatus -ErrorAction Stop; $defender = [pscustomobject]@{AntivirusEnabled=[bool]$status.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$status.RealTimeProtectionEnabled;BehaviorMonitorEnabled=[bool]$status.BehaviorMonitorEnabled;NISEnabled=[bool]$status.NISEnabled} } catch {}
$uac = $null
try { $uac = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction Stop | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop } catch {}
$secureBoot = $null
try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {}
$privacy = @()
foreach ($capability in @('webcam','microphone')) {
  $base = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\$capability"
  $overall = ''
  try { $overall = [string](Get-ItemProperty -Path $base -Name Value -ErrorAction Stop).Value } catch {}
  $privacy += [pscustomobject]@{Capability=$capability;App='(global)';Decision=$overall;LastUsed=''}
  foreach ($key in @(Get-ChildItem -Path $base -ErrorAction SilentlyContinue | Select-Object -First __PRIVACY_LIMIT__)) {
    $value = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
    $privacy += [pscustomobject]@{Capability=$capability;App=[string]$key.PSChildName;Decision=[string]$value.Value;LastUsed=[string]$value.LastUsedTimeStart}
  }
}
[pscustomobject]@{Devices=@($devices);Applications=@($apps);Firewall=@($firewall);Defender=$defender;Uac=$uac;SecureBoot=$secureBoot;Privacy=@($privacy)} | ConvertTo-Json -Depth 8 -Compress
`;

export class ExposureAuditor {
  constructor({ runner = runPowerShell, now = () => new Date(), maxDevices = MAX_DEVICES, maxApplications = MAX_APPLICATIONS, maxPrivacyEntries = MAX_PRIVACY_ENTRIES, policies = {} } = {}) {
    this.runner = runner;
    this.now = now;
    this.maxDevices = clampLimit(maxDevices, MAX_DEVICES);
    this.maxApplications = clampLimit(maxApplications, MAX_APPLICATIONS);
    this.maxPrivacyEntries = clampLimit(maxPrivacyEntries, MAX_PRIVACY_ENTRIES);
    this.policies = normalizePolicies(policies);
  }

  async audit() {
    const startedAt = this.now().toISOString();
    if (process.platform !== 'win32' && this.runner === runPowerShell) return unavailable(startedAt, 'La auditoría de exposición requiere Windows PowerShell.');
    let raw;
    try {
      raw = await this.runner({ deviceLimit: this.maxDevices, applicationLimit: this.maxApplications, privacyLimit: this.maxPrivacyEntries });
    } catch (error) {
      return unavailable(startedAt, `No se pudo tomar el inventario local: ${text(error?.message, 'error de PowerShell', 500)}`);
    }
    return buildReport(raw, {
      startedAt,
      completedAt: this.now().toISOString(),
      maxDevices: this.maxDevices,
      maxApplications: this.maxApplications,
      maxPrivacyEntries: this.maxPrivacyEntries,
      policies: this.policies,
      now: this.now()
    });
  }
}

export async function writeExposureReport(directory, report) {
  await fs.mkdir(directory, { recursive: true });
  const stamp = String(report?.completedAt ?? new Date().toISOString()).replace(/[:.]/g, '-');
  const stem = `exposure-${stamp}-${crypto.randomUUID()}`;
  const json = path.join(directory, `${stem}.json`);
  const csv = path.join(directory, `${stem}.csv`);
  await fs.writeFile(json, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  const rows = [['kind', 'name', 'detail', 'severity', 'publisher', 'version', 'path', 'status']];
  for (const device of asArray(report?.devices)) rows.push(['removable-device', device.label, `${device.drive}:${device.fileSystem}`, 'info', '', '', '', device.status]);
  for (const app of asArray(report?.applications)) rows.push(['application', app.name, app.installLocation, app.policy.severity, app.publisher, app.version, app.installLocation, app.policy.status]);
  for (const setting of asArray(report?.unsafeSettings)) rows.push(['unsafe-setting', setting.title, setting.explanation, setting.severity, '', '', '', setting.id]);
  for (const privacy of asArray(report?.privacy)) rows.push(['privacy', privacy.capability, privacy.app, privacy.severity, '', '', '', privacy.decision]);
  await fs.writeFile(csv, `${rows.map(row => row.map(csvCell).join(',')).join('\r\n')}\r\n`, { flag: 'wx', mode: 0o600 });
  return { json, csv };
}

function buildReport(raw, { startedAt, completedAt, maxDevices, maxApplications, maxPrivacyEntries, policies, now }) {
  const rawDevices = asArray(raw?.Devices ?? raw?.devices);
  const rawApplications = asArray(raw?.Applications ?? raw?.applications);
  const rawPrivacy = asArray(raw?.Privacy ?? raw?.privacy);
  const devices = rawDevices.slice(0, maxDevices).map(normalizeDevice).filter(Boolean);
  const applications = rawApplications.slice(0, maxApplications).map(value => normalizeApplication(value, policies, now)).filter(Boolean);
  const privacy = rawPrivacy.slice(0, maxPrivacyEntries).map(normalizePrivacy).filter(Boolean);
  const unsafeSettings = evaluateUnsafeSettings(raw);
  const expiredExceptions = policies.exceptions.filter(item => item.expiresAt && item.expiresAt <= completedAt);
  const truncated = rawDevices.length > maxDevices || rawApplications.length > maxApplications || rawPrivacy.length > maxPrivacyEntries;
  const firewall = asArray(raw?.Firewall ?? raw?.firewall).slice(0, 8).map(normalizeFirewall).filter(Boolean);
  const defender = normalizeDefender(raw?.Defender ?? raw?.defender);
  return {
    schemaVersion: 1,
    mode: 'audit',
    available: true,
    source: 'windows-powershell',
    startedAt,
    completedAt,
    limitations: [
      'Instantánea local bajo demanda; no hay control continuo de dispositivos.',
      'No se desinstalan aplicaciones ni se modifican Firewall, Defender, UAC o privacidad.',
      'La evaluación de aplicaciones no es un feed CVE: sin una definición local no se afirma que una versión sea segura o vulnerable.',
      'La visibilidad de cámara y micrófono refleja consentimientos de Windows, no uso activo por un proceso.'
    ],
    summary: {
      removableDevices: devices.length,
      applications: applications.length,
      applicationsWithoutVersion: applications.filter(item => !item.version).length,
      applicationsWithoutPublisher: applications.filter(item => !item.publisher).length,
      unsafeSettings: unsafeSettings.length,
      privacyEntries: privacy.length,
      policyIndicators: policies.publishers.length + policies.hashes.length,
      expiredExceptions: expiredExceptions.length,
      truncated
    },
    devices,
    applications,
    unsafeSettings,
    privacy,
    security: { firewall, defender, uac: normalizeUac(raw?.Uac ?? raw?.uac), secureBoot: raw?.SecureBoot === true || raw?.secureBoot === true },
    policies: {
      mode: 'audit',
      publishers: policies.publishers,
      hashes: policies.hashes,
      exceptions: policies.exceptions,
      expiredExceptions,
      enforcementAvailable: false,
      blocking: false
    }
  };
}

function normalizeDevice(value) {
  if (!value || typeof value !== 'object') return null;
  const drive = text(value.DeviceID ?? value.drive, '', 8).toUpperCase();
  if (!/^[A-Z]:$/.test(drive)) return null;
  return {
    id: `drive:${drive}`,
    drive,
    label: text(value.VolumeName ?? value.label, 'Medio extraíble', 260),
    fileSystem: text(value.FileSystem ?? value.fileSystem, 'desconocido', 80),
    sizeBytes: nonNegative(value.Size ?? value.sizeBytes),
    freeBytes: nonNegative(value.FreeSpace ?? value.freeBytes),
    provider: text(value.ProviderName ?? value.provider, '', 260),
    status: 'observed',
    control: 'audit-only'
  };
}

function normalizeApplication(value, policies, now) {
  if (!value || typeof value !== 'object') return null;
  const name = text(value.DisplayName ?? value.name, '', 260);
  if (!name) return null;
  const publisher = text(value.Publisher ?? value.publisher, '', 260);
  const version = text(value.DisplayVersion ?? value.version, '', 120);
  const installLocation = text(value.InstallLocation ?? value.installLocation, '', MAX_PATH);
  const exception = policies.exceptions.find(item => item.name && item.name.toLowerCase() === name.toLowerCase());
  const expired = Boolean(exception?.expiresAt && exception.expiresAt <= now.toISOString());
  const publisherMatch = publisher && policies.publishers.some(item => publisher.toLowerCase().includes(item.toLowerCase()));
  const status = expired ? 'expired-exception' : exception ? 'exception' : publisherMatch ? 'publisher-allowed' : 'unmatched';
  const severity = expired ? 'medium' : status === 'unmatched' && policies.publishers.length + policies.hashes.length > 0 ? 'low' : 'info';
  return {
    name,
    publisher,
    version,
    installDate: text(value.InstallDate ?? value.installDate, '', 32),
    installLocation,
    uninstallString: text(value.UninstallString ?? value.uninstallString, '', MAX_TEXT),
    estimatedSizeKb: nonNegative(value.EstimatedSize ?? value.estimatedSizeKb),
    policy: { status, severity, hash: null, enforcement: 'audit-only', explanation: expired ? 'La excepción local ha caducado y requiere revisión.' : status === 'publisher-allowed' ? 'El editor coincide con un indicador permitido local.' : 'Inventario local sin una decisión de seguridad automática.' }
  };
}

function normalizePrivacy(value) {
  if (!value || typeof value !== 'object') return null;
  const capability = ['webcam', 'microphone'].includes(String(value.Capability ?? value.capability).toLowerCase()) ? String(value.Capability ?? value.capability).toLowerCase() : '';
  if (!capability) return null;
  const decision = normalizeDecision(value.Decision ?? value.decision);
  return { capability, app: text(value.App ?? value.app, '(global)', 260), decision, lastUsed: date(value.LastUsed ?? value.lastUsed), severity: decision === 'allowed' && text(value.App ?? value.app, '(global)') === '(global)' ? 'low' : 'info', explanation: decision === 'allowed' ? 'Consentimiento de Windows concedido; no implica uso activo.' : 'Consentimiento de Windows no concedido o no disponible.' };
}

function evaluateUnsafeSettings(raw) {
  const findings = [];
  const firewall = asArray(raw?.Firewall ?? raw?.firewall).filter(item => item && item.Enabled === false && item.Name);
  if (firewall.length) findings.push({ id: 'firewall-profile-disabled', title: 'Perfil de Firewall desactivado', severity: 'high', explanation: `${firewall.length} perfil(es) de Firewall de Windows aparecen desactivados; revisa la configuración del sistema.` });
  const defender = raw?.Defender ?? raw?.defender;
  if (defender && (defender.RealTimeProtectionEnabled === false || defender.realTimeProtectionEnabled === false)) findings.push({ id: 'defender-realtime-disabled', title: 'Protección en tiempo real desactivada', severity: 'high', explanation: 'Microsoft Defender informa de que la protección en tiempo real no está activa.' });
  const uac = raw?.Uac ?? raw?.uac;
  if (uac && Number(uac.EnableLUA ?? uac.enableLUA) === 0) findings.push({ id: 'uac-disabled', title: 'UAC desactivado', severity: 'high', explanation: 'El control de cuentas de usuario aparece desactivado.' });
  if (raw?.SecureBoot === false || raw?.secureBoot === false) findings.push({ id: 'secure-boot-disabled', title: 'Secure Boot no activo', severity: 'medium', explanation: 'Windows no confirma Secure Boot en esta instantánea; puede no estar disponible en firmware heredado.' });
  return findings;
}

function normalizeFirewall(value) { return value && typeof value === 'object' ? { name: text(value.Name ?? value.name, '', 40), enabled: value.Enabled === true || value.enabled === true, defaultInboundAction: text(value.DefaultInboundAction ?? value.defaultInboundAction, '', 40), defaultOutboundAction: text(value.DefaultOutboundAction ?? value.defaultOutboundAction, '', 40) } : null; }
function normalizeDefender(value) { return value && typeof value === 'object' ? { antivirusEnabled: value.AntivirusEnabled === true || value.antivirusEnabled === true, realTimeProtectionEnabled: value.RealTimeProtectionEnabled === true || value.realTimeProtectionEnabled === true, behaviorMonitorEnabled: value.BehaviorMonitorEnabled === true || value.behaviorMonitorEnabled === true, networkInspectionEnabled: value.NISEnabled === true || value.networkInspectionEnabled === true } : null; }
function normalizeUac(value) { return value && typeof value === 'object' ? { enableLUA: Number(value.EnableLUA ?? value.enableLUA) === 1, consentPromptBehaviorAdmin: nonNegative(value.ConsentPromptBehaviorAdmin ?? value.consentPromptBehaviorAdmin), promptOnSecureDesktop: Number(value.PromptOnSecureDesktop ?? value.promptOnSecureDesktop) === 1 } : null; }
function normalizePolicies(value) {
  const input = value && typeof value === 'object' ? value : {};
  return {
    publishers: unique(asArray(input.publishers).map(item => text(item, '', 260)).filter(Boolean)).slice(0, MAX_POLICIES),
    hashes: unique(asArray(input.hashes).map(item => text(item, '', 128).toLowerCase()).filter(item => /^[a-f0-9]{64}$/.test(item))).slice(0, MAX_POLICIES),
    exceptions: asArray(input.exceptions).map(item => ({ name: text(item?.name, '', 260), expiresAt: date(item?.expiresAt), reason: text(item?.reason, '', 500) })).filter(item => item.name).slice(0, MAX_POLICIES)
  };
}
function normalizeDecision(value) { const lowered = text(value).toLowerCase(); return lowered === 'allow' || lowered === 'allowed' ? 'allowed' : lowered === 'deny' || lowered === 'denied' ? 'denied' : 'unknown'; }
function unavailable(at, error) { return { schemaVersion: 1, mode: 'audit', available: false, source: 'unavailable', startedAt: at, completedAt: at, error, limitations: ['La auditoría de exposición local requiere Windows PowerShell.'], summary: { removableDevices: 0, applications: 0, applicationsWithoutVersion: 0, applicationsWithoutPublisher: 0, unsafeSettings: 0, privacyEntries: 0, policyIndicators: 0, expiredExceptions: 0, truncated: false }, devices: [], applications: [], unsafeSettings: [], privacy: [], security: { firewall: [], defender: null, uac: null, secureBoot: false }, policies: { mode: 'audit', publishers: [], hashes: [], exceptions: [], expiredExceptions: [], enforcementAvailable: false, blocking: false } }; }
function runPowerShell({ deviceLimit, applicationLimit, privacyLimit }) { return new Promise((resolve, reject) => { const script = SCRIPT.replace('__DEVICE_LIMIT__', String(deviceLimit)).replace('__APPLICATION_LIMIT__', String(applicationLimit)).replace('__PRIVACY_LIMIT__', String(privacyLimit)); const encoded = Buffer.from(script, 'utf16le').toString('base64'); execFile(POWERSHELL, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { windowsHide: true, timeout: 30_000, maxBuffer: 8 * 1024 * 1024, env: { ...process.env, PSModulePath: [WINDOWS_MODULES, process.env.PSModulePath].filter(Boolean).join(';') } }, (error, stdout) => { if (error) return reject(error); try { resolve(JSON.parse(stdout.trim())); } catch (parseError) { reject(parseError); } }); }); }
function csvCell(value) { let output = String(value ?? '').replace(/\r?\n/g, ' '); if (/^[=+\-@]/.test(output)) output = `'${output}`; return `"${output.replace(/"/g, '""')}"`; }
function asArray(value) { return Array.isArray(value) ? value : value == null ? [] : [value]; }
function unique(values) { return [...new Set(values)]; }
function clampLimit(value, maximum) { return Math.max(1, Math.min(maximum, Number.isFinite(Number(value)) ? Math.trunc(Number(value)) : maximum)); }
function text(value, fallback = '', maximum = 256) { return typeof value === 'string' && value.trim() ? value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, maximum) : fallback; }
function nonNegative(value) { const number = Number(value); return Number.isFinite(number) && number >= 0 ? Math.min(Math.trunc(number), Number.MAX_SAFE_INTEGER) : 0; }
function date(value) { if (!value) return null; const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString(); }
