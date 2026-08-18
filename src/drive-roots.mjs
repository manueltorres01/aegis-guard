import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const MAX_DRIVE_ROOTS = 32;
const POWERSHELL_DRIVE_QUERY = [
  "$ErrorActionPreference = 'Stop';",
  '[System.IO.DriveInfo]::GetDrives()',
  "| Where-Object { $_.IsReady -and @('Fixed','Removable','CDRom','Ram') -contains $_.DriveType.ToString() }",
  "| ForEach-Object { '{0}|{1}' -f $_.DriveType, $_.RootDirectory.FullName }"
].join(' ');

export async function discoverWindowsDriveRoots({ execFileImpl = execFileAsync, environment = process.env } = {}) {
  if (process.platform !== 'win32') return [];
  let candidates;
  try {
    const executable = resolveSystemPowerShell(environment);
    const executableStat = await fs.stat(executable);
    if (!executableStat.isFile()) throw new Error('PowerShell executable is not a regular file');
    const { stdout } = await execFileImpl(executable, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', POWERSHELL_DRIVE_QUERY
    ], {
      encoding: 'utf8',
      timeout: 5_000,
      maxBuffer: 32 * 1024,
      windowsHide: true
    });
    candidates = parseWindowsDriveRecords(stdout);
  } catch (cause) {
    throw driveEnumerationError('Unable to enumerate local Windows drives', cause);
  }
  if (!candidates.length) throw driveEnumerationError('Windows returned no valid local drive roots');

  const roots = [];
  const seen = new Set();
  for (const candidate of candidates.slice(0, MAX_DRIVE_ROOTS)) {
    try {
      const canonical = await fs.realpath(candidate.root);
      const stat = await fs.stat(canonical);
      if (!stat.isDirectory()) throw new Error('Drive root is not a directory');
      const normalized = path.parse(canonical).root;
      const key = normalized.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        roots.push(normalized);
      }
    } catch (cause) {
      // Only genuinely removable media is allowed to disappear after the
      // authoritative enumeration. Silently dropping a fixed root would make
      // a Full report claim coverage it did not achieve.
      if (candidate.type === 'Removable') continue;
      throw driveEnumerationError('A local Windows drive became unavailable before scanning', cause);
    }
  }
  return roots;
}

export function resolveSystemPowerShell(environment = process.env) {
  const systemRoot = String(environment?.SystemRoot ?? '');
  if (!path.win32.isAbsolute(systemRoot)) throw new Error('SystemRoot is unavailable or invalid');
  const normalizedRoot = path.win32.resolve(systemRoot);
  const executable = path.win32.resolve(normalizedRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const relative = path.win32.relative(normalizedRoot, executable);
  if (!relative || relative === '..' || relative.startsWith(`..${path.win32.sep}`) || path.win32.isAbsolute(relative)) {
    throw new Error('Resolved PowerShell path escapes SystemRoot');
  }
  return executable;
}

export function parseWindowsDriveRoots(output) {
  return parseWindowsDriveRecords(output).map(record => record.root);
}

export function parseWindowsDriveRecords(output) {
  const roots = [];
  const seen = new Set();
  for (const line of String(output ?? '').split(/\r?\n/)) {
    const match = line.trim().match(/^(?:(Fixed|Removable|CDRom|Ram)\|)?([A-Za-z]):(?:[\\/])?$/i);
    if (!match) continue;
    const root = `${match[2].toUpperCase()}:\\`;
    if (!seen.has(root)) {
      seen.add(root);
      const canonicalType = match[1]
        ? ({ fixed: 'Fixed', removable: 'Removable', cdrom: 'CDRom', ram: 'Ram' })[match[1].toLowerCase()]
        : 'Unknown';
      roots.push({ root, type: canonicalType });
    }
  }
  return roots.slice(0, MAX_DRIVE_ROOTS);
}

function driveEnumerationError(message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = 'DRIVE_ENUMERATION_FAILED';
  return error;
}
