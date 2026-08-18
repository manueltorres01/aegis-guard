import fs from 'node:fs/promises';
import path from 'node:path';

export async function loadJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

export function resolveInside(base, candidate) {
  const root = path.resolve(base);
  const target = path.resolve(root, candidate);
  if (target !== root && !target.startsWith(root + path.sep)) {
    throw new Error('Unsafe path outside managed directory');
  }
  return target;
}

export async function pathExists(file) {
  try { await fs.access(file); return true; } catch { return false; }
}

export function formatBytes(bytes) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return `${value.toFixed(i ? 1 : 0)} ${units[i]}`;
}
