import os from 'node:os';
import path from 'node:path';

const PLATFORM_FAMILIES = Object.freeze({
  win32: 'windows',
  linux: 'linux',
  darwin: 'macos'
});

export function getPlatformProfile({
  platform = process.platform,
  arch = process.arch,
  release = os.release(),
  homeDirectory = os.homedir()
} = {}) {
  const normalizedPlatform = typeof platform === 'string' ? platform.trim().toLowerCase() : 'unknown';
  const family = PLATFORM_FAMILIES[normalizedPlatform] ?? 'unknown';
  const supported = family === 'windows' || family === 'linux';
  const linuxPreview = family === 'linux';

  return {
    schemaVersion: 1,
    platform: normalizedPlatform,
    family,
    arch: String(arch || 'unknown').slice(0, 32),
    release: String(release || '').slice(0, 128),
    supported,
    mode: family === 'windows' ? 'windows-desktop' : linuxPreview ? 'linux-analysis-preview' : 'unsupported',
    defaultRoot: defaultScanRoot({ platform: normalizedPlatform, homeDirectory }),
    capabilities: {
      portableScan: supported,
      cli: supported,
      encryptedQuarantine: supported,
      linuxAudit: linuxPreview,
      desktop: family === 'windows',
      realtimeAudit: family === 'windows',
      windowsAuthenticode: family === 'windows',
      nativeWindowsTelemetry: false,
      enforcement: false
    },
    limitations: linuxPreview
      ? [
          'Linux se ofrece inicialmente como vista previa de análisis y auditoría de usuario.',
          'No hay servicio systemd, fanotify, eBPF, bloqueo de red ni prevención en tiempo real.',
          'La compatibilidad validada comienza con una distribución Ubuntu LTS y Node.js 20 o posterior.'
        ]
      : family === 'windows'
        ? ['Las capacidades nativas de Windows requieren el entorno y permisos documentados.']
        : ['Esta plataforma no está soportada por la versión actual.']
  };
}

export function defaultScanRoot({ platform = process.platform, homeDirectory = os.homedir() } = {}) {
  const candidate = typeof homeDirectory === 'string' && homeDirectory.trim() ? homeDirectory.trim() : process.cwd();
  if (platform === 'win32') return path.win32.resolve(candidate);
  if (platform === 'linux') return path.posix.resolve(candidate);
  return path.resolve(process.cwd());
}

export function normalizePlatformPath(value, { platform = process.platform } = {}) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError('Path must be a non-empty string');
  const resolved = platform === 'win32' ? path.win32.resolve(value) : platform === 'linux' ? path.posix.resolve(value) : path.resolve(value);
  return platform === 'win32' ? resolved.toLowerCase() : resolved;
}

export function isPortablePlatform(platform = process.platform) {
  return platform === 'win32' || platform === 'linux';
}
