import fs from 'node:fs/promises';
import os from 'node:os';
import { getPlatformProfile } from './platform-adapter.mjs';

const OS_RELEASE_PATH = '/etc/os-release';
const OS_RELEASE_KEYS = ['ID', 'NAME', 'PRETTY_NAME', 'VERSION_ID'];

export async function collectLinuxAudit({
  platform = process.platform,
  fsImpl = fs,
  release = os.release(),
  arch = process.arch,
  homeDirectory = os.homedir(),
  uid = typeof process.getuid === 'function' ? process.getuid() : null
} = {}) {
  const startedAt = new Date().toISOString();
  const profile = getPlatformProfile({ platform, arch, release, homeDirectory });
  if (profile.family !== 'linux') {
    return {
      schemaVersion: 1,
      mode: 'audit',
      available: false,
      source: 'unavailable',
      startedAt,
      completedAt: startedAt,
      profile,
      distribution: {},
      uid,
      error: 'La auditoría Linux solo está disponible en Linux.',
      limitations: profile.limitations
    };
  }

  let distribution = {};
  const limitations = [...profile.limitations];
  try {
    distribution = parseOsRelease(await fsImpl.readFile(OS_RELEASE_PATH, 'utf8'));
  } catch {
    limitations.push('No se pudo leer /etc/os-release; se conserva la información del kernel.');
  }

  return {
    schemaVersion: 1,
    mode: 'audit',
    available: true,
    source: 'linux-userspace',
    startedAt,
    completedAt: new Date().toISOString(),
    profile,
    distribution,
    kernel: { release: String(release || '').slice(0, 128), arch: String(arch || '').slice(0, 32) },
    uid: Number.isSafeInteger(uid) ? uid : null,
    roots: [{ path: profile.defaultRoot, kind: 'home', status: 'observed' }],
    capabilities: profile.capabilities,
    limitations
  };
}

export function parseOsRelease(value) {
  if (typeof value !== 'string') return {};
  const parsed = {};
  for (const line of value.split(/\r?\n/)) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (!match || !OS_RELEASE_KEYS.includes(match[1])) continue;
    let text = match[2].trim();
    if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) text = text.slice(1, -1);
    parsed[match[1].toLowerCase()] = text.replaceAll('\\"', '"').slice(0, 200);
  }
  return parsed;
}
