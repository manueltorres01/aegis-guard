import path from 'node:path';

const UUID_SOURCE = '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const UUID = new RegExp(`^${UUID_SOURCE}$`, 'i');

export function quarantineStagingName(id) {
  assertUuid(id);
  return `.aegis-${id}.quarantine-tmp`;
}

export function restoreStagingName(id, nonce) {
  assertUuid(id);
  assertUuid(nonce);
  return `.aegis-${id}-${nonce}.restore-tmp`;
}

export function normalizeInternalPath(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function assertUuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('Invalid internal identifier');
}
