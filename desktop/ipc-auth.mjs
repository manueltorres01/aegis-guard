import crypto from 'node:crypto';

export function signWorkerMessage(message, key) {
  const material = decodeKey(key);
  const unsigned = withoutAuth(message);
  const auth = crypto.createHmac('sha256', material).update(JSON.stringify(unsigned)).digest('base64');
  return { ...unsigned, auth };
}

export function verifyWorkerMessage(message, key) {
  if (!message || typeof message !== 'object' || Array.isArray(message) || typeof message.auth !== 'string') return null;
  const material = decodeKey(key);
  const unsigned = withoutAuth(message);
  const expected = crypto.createHmac('sha256', material).update(JSON.stringify(unsigned)).digest();
  let actual;
  try { actual = Buffer.from(message.auth, 'base64'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  return unsigned;
}

function withoutAuth(message) {
  const output = {};
  for (const [key, value] of Object.entries(message)) if (key !== 'auth') output[key] = value;
  return output;
}

function decodeKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new Error('Invalid IPC authentication key');
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('Invalid IPC authentication key');
  return key;
}
