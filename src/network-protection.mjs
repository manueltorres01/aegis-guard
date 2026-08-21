import { execFile } from 'node:child_process';

const POWERSHELL = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const WINDOWS_MODULES = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\Modules`;
const RULE_GROUP = 'Aegis Guard 0.7.0 Indicators';
const MAX_ADDRESSES = 256;
const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$group = '__GROUP__'
$addresses = @(__ADDRESSES__)
if ('__OPERATION__' -eq 'remove') {
  Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
  [pscustomobject]@{Operation='remove';Applied=0;Skipped=0;Rules=@()} | ConvertTo-Json -Compress
  exit 0
}
$existing = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
$desiredNames = @()
$created = @()
try {
  foreach ($address in $addresses) {
    $safe = ([string]$address).Replace(':','-').Replace('/','-')
    $name = "Aegis Guard Indicator $safe"
    $desiredNames += $name
    if (-not ($existing | Where-Object { $_.DisplayName -eq $name })) {
      New-NetFirewallRule -DisplayName $name -Group $group -Direction Outbound -Action Block -Profile Any -Protocol Any -RemoteAddress $address -Description 'Aegis Guard reversible indicator rule' -ErrorAction Stop | Out-Null
      $created += $name
    }
  }
  $existing | Where-Object { $_.DisplayName -notin $desiredNames } | Remove-NetFirewallRule -ErrorAction Stop
  [pscustomobject]@{Operation='apply';Applied=$desiredNames.Count;Skipped=0;Rules=@($desiredNames)} | ConvertTo-Json -Compress
} catch {
  foreach ($name in $created) { Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue }
  throw
}
`;

export class NetworkProtector {
  constructor({ runner = runPowerShell, now = () => new Date(), maxAddresses = MAX_ADDRESSES } = {}) {
    this.runner = runner;
    this.now = now;
    this.maxAddresses = Math.max(1, Math.min(MAX_ADDRESSES, Number(maxAddresses) || MAX_ADDRESSES));
    this.state = emptyState();
  }

  async apply(indicators = {}) {
    const addresses = normalizeAddresses(indicators.ips).slice(0, this.maxAddresses);
    const skippedDomains = normalizeDomains(indicators.domains);
    const changedAt = this.now().toISOString();
    if (process.platform !== 'win32' && this.runner === runPowerShell) {
      this.state = { ...this.state, error: 'Windows Firewall solo está disponible en Windows.', lastChangedAt: changedAt };
      return { ...this.state, attempted: addresses.length, skippedDomains };
    }
    try {
      const result = await this.runner({ operation: 'apply', addresses, group: RULE_GROUP });
      const applied = Math.min(addresses.length, nonNegative(result?.Applied ?? result?.applied));
      const rules = array(result?.Rules ?? result?.rules).map(item => text(item, 120)).filter(Boolean).slice(0, this.maxAddresses);
      this.state = { ...this.state, active: applied > 0, addressesBlocked: applied, domainsPending: skippedDomains.length, skippedDomains, rules, lastChangedAt: changedAt, error: null };
      return { ...this.state, attempted: addresses.length, applied, skippedDomains };
    } catch (error) {
      this.state = { ...this.state, error: text(error?.message, 500) || 'No se pudieron aplicar las reglas del Firewall.', lastChangedAt: changedAt };
      return { ...this.state, attempted: addresses.length, applied: 0, skippedDomains };
    }
  }

  async remove() {
    const changedAt = this.now().toISOString();
    if (process.platform !== 'win32' && this.runner === runPowerShell) {
      this.state = { ...emptyState(), error: 'Windows Firewall solo está disponible en Windows.', lastChangedAt: changedAt };
      return { ...this.state };
    }
    try {
      await this.runner({ operation: 'remove', addresses: [], group: RULE_GROUP });
      this.state = { ...emptyState(), lastChangedAt: changedAt };
      return { ...this.state };
    } catch (error) {
      this.state = { ...this.state, error: text(error?.message, 500) || 'No se pudieron retirar las reglas del Firewall.', lastChangedAt: changedAt };
      return { ...this.state };
    }
  }

  status() { return { ...this.state }; }
}

function runPowerShell({ operation, addresses, group }) {
  return new Promise((resolve, reject) => {
    const safeAddresses = normalizeAddresses(addresses).map(value => `'${value.replaceAll("'", "''")}'`).join(',');
    const script = SCRIPT.replace('__OPERATION__', operation === 'remove' ? 'remove' : 'apply').replace('__GROUP__', group.replaceAll("'", "''")).replace('__ADDRESSES__', safeAddresses);
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    execFile(POWERSHELL, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024, env: { ...process.env, PSModulePath: [WINDOWS_MODULES, process.env.PSModulePath].filter(Boolean).join(';') } }, (error, stdout) => {
      if (error) return reject(error);
      try { resolve(JSON.parse(stdout.trim())); } catch (parseError) { reject(parseError); }
    });
  });
}

function emptyState() { return { mode: 'audit', active: false, addressesBlocked: 0, domainsPending: 0, skippedDomains: [], rules: [], lastChangedAt: null, error: null, blocking: false, reversible: true, group: RULE_GROUP }; }
function normalizeAddresses(values) {
  return [...new Set(array(values).map(item => text(item, 80)).filter(isAddress))];
}
function isAddress(value) {
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
  if (ipv4) return value.split('.').every(part => Number(part) <= 255);
  return /^[0-9a-f:]+(?:\/\d{1,3})?$/i.test(value) && value.includes(':');
}
function normalizeDomains(values) { return [...new Set(array(values).map(item => text(item, 253).replace(/^\*\./, '').toLowerCase()).filter(item => /^[a-z0-9.-]+$/.test(item) && item.includes('.')))]; }
function array(value) { return Array.isArray(value) ? value : value == null ? [] : [value]; }
function text(value, maximum = 256) { return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, maximum) : ''; }
function nonNegative(value) { const number = Number(value); return Number.isFinite(number) && number >= 0 ? Math.trunc(number) : 0; }
