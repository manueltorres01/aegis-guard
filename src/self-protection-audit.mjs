import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const MAX_FILES = 256;
const MAX_TEXT = 1_000;

// These are the files whose modification would change the local security
// decision path. The manifest is deliberately separate so a future signed
// release pipeline can replace the local baseline with a verified one.
export const DEFAULT_INTEGRITY_TARGETS = Object.freeze([
  'package.json',
  'config/default.json',
  'config/definition-keys.json',
  'config/definition-feed.json',
  'config/threat-intel.json',
  'definitions/signatures.json',
  'definitions/network-indicators.json',
  'definitions/application-policies.json',
  'src/definition-security.mjs',
  'src/definition-updater.mjs',
  'src/definition-feed-service.mjs',
  'src/threat-intel-store.mjs',
  'desktop/main.mjs',
  'desktop/preload.cjs',
  'desktop/scan-worker.mjs',
  'desktop/ipc-contracts.mjs',
  'desktop/renderer/app.js',
  'src/app-service.mjs',
  'src/engine.mjs',
  'src/self-protection-audit.mjs'
]);

export class SelfProtectionAuditor {
  constructor({ baseDirectory, manifestPath = path.join(baseDirectory, 'definitions', 'integrity-manifest.json'), targets = DEFAULT_INTEGRITY_TARGETS, now = () => new Date() } = {}) {
    this.baseDirectory = path.resolve(baseDirectory);
    this.manifestPath = path.resolve(manifestPath);
    this.targets = [...new Set(targets)].filter(value => typeof value === 'string' && value.length > 0).slice(0, MAX_FILES);
    this.now = now;
  }

  async audit() {
    const startedAt = this.now().toISOString();
    let manifest;
    try {
      manifest = normalizeManifest(JSON.parse(await fs.readFile(this.manifestPath, 'utf8')));
    } catch (error) {
      return unavailable(startedAt, `No hay un manifiesto de integridad válido: ${text(error?.message, 'archivo no disponible')}`);
    }

    const expected = new Map(manifest.files.map(item => [item.path, item.sha256]));
    const items = [];
    for (const relative of this.targets) {
      const safeRelative = normalizeRelativePath(relative);
      if (!safeRelative) continue;
      const expectedHash = expected.get(safeRelative);
      const absolute = path.resolve(this.baseDirectory, safeRelative);
      if (!isWithin(this.baseDirectory, absolute)) continue;
      try {
        const actualHash = await hashFile(absolute);
        items.push({ path: safeRelative, status: expectedHash ? actualHash === expectedHash ? 'verified' : 'modified' : 'untracked', expectedSha256: expectedHash ?? null, actualSha256: actualHash, sizeBytes: (await fs.stat(absolute)).size });
      } catch (error) {
        items.push({ path: safeRelative, status: 'missing', expectedSha256: expectedHash ?? null, actualSha256: null, sizeBytes: 0, error: text(error?.code ?? error?.message, 'no se pudo leer') });
      }
    }
    const completedAt = this.now().toISOString();
    const counts = {
      total: items.length,
      verified: items.filter(item => item.status === 'verified').length,
      modified: items.filter(item => item.status === 'modified').length,
      missing: items.filter(item => item.status === 'missing').length,
      untracked: items.filter(item => item.status === 'untracked').length
    };
    return {
      schemaVersion: 1,
      mode: 'audit',
      available: true,
      source: 'local-manifest',
      startedAt,
      completedAt,
      manifestVersion: manifest.version,
      manifestGeneratedAt: manifest.generatedAt,
      signature: { status: manifest.signature ? 'present-unverified' : 'not-configured', algorithm: manifest.signature?.algorithm ?? null },
      summary: { ...counts, healthy: counts.modified === 0 && counts.missing === 0, truncated: items.length < this.targets.length },
      items,
      limitations: [
        'La línea base local no sustituye una firma de código ni una raíz de confianza del sistema.',
        'El modo auditoría informa de cambios, pero no repara, bloquea ni restaura archivos automáticamente.',
        'La reputación remota permanece desactivada hasta que el usuario la habilite explícitamente y exista una política de retención.'
      ],
      enforcement: { mode: 'audit', blocking: false, repairAvailable: false, serviceProtected: false }
    };
  }
}

export async function writeSelfProtectionReport(directory, report) {
  await fs.mkdir(directory, { recursive: true });
  const stamp = String(report?.completedAt ?? new Date().toISOString()).replace(/[:.]/g, '-');
  const stem = `integrity-${stamp}-${crypto.randomUUID()}`;
  const json = path.join(directory, `${stem}.json`);
  const csv = path.join(directory, `${stem}.csv`);
  await fs.writeFile(json, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  const rows = [['path', 'status', 'expectedSha256', 'actualSha256', 'sizeBytes', 'error']];
  for (const item of Array.isArray(report?.items) ? report.items : []) rows.push([item.path, item.status, item.expectedSha256 ?? '', item.actualSha256 ?? '', item.sizeBytes ?? 0, item.error ?? '']);
  await fs.writeFile(csv, `${rows.map(row => row.map(csvCell).join(',')).join('\r\n')}\r\n`, { flag: 'wx', mode: 0o600 });
  return { json, csv };
}

export async function createIntegrityManifest(baseDirectory, { targets = DEFAULT_INTEGRITY_TARGETS, version = '2026.08.20-local' } = {}) {
  const root = path.resolve(baseDirectory);
  const files = [];
  for (const candidate of [...new Set(targets)].slice(0, MAX_FILES)) {
    const relative = normalizeRelativePath(candidate);
    if (!relative) continue;
    const absolute = path.resolve(root, relative);
    if (!isWithin(root, absolute)) continue;
    try { files.push({ path: relative, sha256: await hashFile(absolute) }); }
    catch { /* A platform-specific target is omitted from the release baseline. */ }
  }
  return { schemaVersion: 1, version, generatedAt: new Date().toISOString(), signature: null, files };
}

function normalizeManifest(value) {
  const input = value && typeof value === 'object' ? value : {};
  const files = Array.isArray(input.files) ? input.files.slice(0, MAX_FILES).map(item => ({ path: normalizeRelativePath(item?.path), sha256: typeof item?.sha256 === 'string' && /^[a-f0-9]{64}$/i.test(item.sha256) ? item.sha256.toLowerCase() : null })).filter(item => item.path && item.sha256) : [];
  return { version: text(input.version, 'unknown', 120), generatedAt: typeof input.generatedAt === 'string' ? input.generatedAt : null, signature: input.signature && typeof input.signature === 'object' ? { algorithm: text(input.signature.algorithm, 'unknown', 80) } : null, files };
}

function normalizeRelativePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_TEXT || path.isAbsolute(value)) return null;
  const normalized = value.replaceAll('\\', '/');
  if (normalized.split('/').some(part => !part || part === '.' || part === '..')) return null;
  return normalized;
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function hashFile(file) {
  const bytes = await fs.readFile(file);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function unavailable(at, error) {
  return { schemaVersion: 1, mode: 'audit', available: false, source: 'unavailable', startedAt: at, completedAt: at, error: text(error, 'No hay un manifiesto de integridad válido'), signature: { status: 'not-configured', algorithm: null }, summary: { total: 0, verified: 0, modified: 0, missing: 0, untracked: 0, healthy: false, truncated: false }, items: [], limitations: ['La auditoría de integridad requiere un manifiesto local generado durante el empaquetado.'], enforcement: { mode: 'audit', blocking: false, repairAvailable: false, serviceProtected: false } };
}

function text(value, fallback = '', maximum = MAX_TEXT) {
  return typeof value === 'string' && value.trim() ? value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, maximum) : fallback;
}

function csvCell(value) {
  let output = String(value ?? '').replace(/\r?\n/g, ' ');
  if (/^[=+\-@]/.test(output)) output = `'${output}`;
  return `"${output.replaceAll('"', '""')}"`;
}
