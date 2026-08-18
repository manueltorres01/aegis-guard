import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

export const TARGET_TTL_MS = 10 * 60 * 1_000;
const DEFAULT_MAX_TARGETS = 64;

export class TargetVault {
  constructor({ ttlMs = TARGET_TTL_MS, maxTargets = DEFAULT_MAX_TARGETS, now = () => Date.now() } = {}) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new TypeError('ttlMs must be a positive integer');
    if (!Number.isSafeInteger(maxTargets) || maxTargets <= 0) throw new TypeError('maxTargets must be a positive integer');
    if (typeof now !== 'function') throw new TypeError('now must be a function');
    this.ttlMs = ttlMs;
    this.maxTargets = maxTargets;
    this.now = now;
    this.targets = new Map();
  }

  async add(targetPath, kind) {
    if (!['file', 'directory'].includes(kind)) throw targetError('TARGET_CHANGED', 'Invalid target kind');
    const selectedPath = path.resolve(targetPath);
    const selectedStat = await fs.lstat(selectedPath).catch(() => null);
    if (!selectedStat || selectedStat.isSymbolicLink()) throw targetError('TARGET_CHANGED', 'Selected target is unavailable');

    const canonicalPath = await fs.realpath(selectedPath).catch(() => null);
    if (!canonicalPath) throw targetError('TARGET_CHANGED', 'Selected target is unavailable');
    const canonicalStat = await fs.lstat(canonicalPath).catch(() => null);
    if (!canonicalStat || canonicalStat.isSymbolicLink() || !hasExpectedType(canonicalStat, kind)) {
      throw targetError('TARGET_CHANGED', 'Selected target changed type');
    }

    const createdAt = this.now();
    this.prune(createdAt);
    const id = crypto.randomUUID();
    const target = {
      id,
      path: path.resolve(canonicalPath),
      selectedPath,
      kind,
      label: targetLabel(canonicalPath, kind),
      mode: 'deep',
      createdAt,
      identity: snapshotIdentity(canonicalStat, kind)
    };
    this.targets.set(id, target);
    while (this.targets.size > this.maxTargets) this.targets.delete(this.targets.keys().next().value);
    return publicRecord(target);
  }

  async consume(id) {
    const target = this.targets.get(id);
    if (target) this.targets.delete(id);
    if (!target || this.now() - target.createdAt > this.ttlMs) {
      throw targetError('TARGET_EXPIRED', 'Selected target expired');
    }

    const selectedStat = await fs.lstat(target.selectedPath).catch(() => null);
    if (!selectedStat || selectedStat.isSymbolicLink()) throw targetError('TARGET_CHANGED', 'Selected target changed');
    const canonicalPath = await fs.realpath(target.selectedPath).catch(() => null);
    if (!canonicalPath || normalizePath(canonicalPath) !== normalizePath(target.path)) {
      throw targetError('TARGET_CHANGED', 'Selected target changed');
    }
    const current = await fs.lstat(canonicalPath).catch(() => null);
    if (
      !current
      || current.isSymbolicLink()
      || !hasExpectedType(current, target.kind)
      || identityChanged(target.identity, snapshotIdentity(current, target.kind), target.kind)
    ) {
      throw targetError('TARGET_CHANGED', 'Selected target changed');
    }
    return publicRecord({ ...target, path: path.resolve(canonicalPath) });
  }

  prune(now = this.now()) {
    for (const [id, target] of this.targets) {
      if (now - target.createdAt > this.ttlMs) this.targets.delete(id);
    }
  }
}

function publicRecord(target) {
  return {
    id: target.id,
    path: target.path,
    kind: target.kind,
    label: target.label,
    mode: target.mode,
    createdAt: target.createdAt
  };
}

function snapshotIdentity(stat, kind) {
  return {
    dev: Number(stat.dev) || 0,
    ino: Number(stat.ino) || 0,
    birthtimeMs: Number(stat.birthtimeMs) || 0,
    size: kind === 'file' ? Number(stat.size) : 0,
    mtimeMs: kind === 'file' ? Number(stat.mtimeMs) : 0
  };
}

function identityChanged(before, after, kind) {
  if (before.dev && after.dev && before.dev !== after.dev) return true;
  if (before.ino && after.ino && before.ino !== after.ino) return true;
  if (before.birthtimeMs && after.birthtimeMs && before.birthtimeMs !== after.birthtimeMs) return true;
  return kind === 'file' && (before.size !== after.size || before.mtimeMs !== after.mtimeMs);
}

function hasExpectedType(stat, kind) {
  return kind === 'directory' ? stat.isDirectory() : stat.isFile();
}

function normalizePath(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function targetLabel(targetPath, kind) {
  const fallback = kind === 'directory' ? 'Unidad seleccionada' : 'Archivo seleccionado';
  return String(path.basename(targetPath) || fallback).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 240);
}

function targetError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
