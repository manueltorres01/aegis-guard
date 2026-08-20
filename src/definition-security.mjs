import crypto from 'node:crypto';

export function validateDefinitions(definitions) {
  if (!definitions || typeof definitions !== 'object' || Array.isArray(definitions)) throw new Error('Definitions must be an object');
  if (!Number.isSafeInteger(definitions.version) || definitions.version < 1) throw new Error('Definitions version is invalid');
  if (!Number.isFinite(Date.parse(definitions.generatedAt))) throw new Error('Definitions timestamp is invalid');
  validateHashMap(definitions.sha256, 'sha256');
  validateHashMap(definitions.puaSha256 ?? {}, 'puaSha256');
  if (!Array.isArray(definitions.patterns) || definitions.patterns.length > 50_000) throw new Error('Definitions patterns are invalid');
  for (const rule of definitions.patterns) {
    if (!rule || typeof rule !== 'object' || typeof rule.id !== 'string' || rule.id.length > 200) throw new Error('Definition rule is invalid');
    if (!Number.isFinite(rule.score) || rule.score < 0 || rule.score > 100) throw new Error('Definition score is invalid');
    const validLiteral = typeof rule.literalBase64 === 'string' && rule.literalBase64.length <= 2 * 1024 * 1024 && isCanonicalBase64(rule.literalBase64);
    const validHex = typeof rule.hex === 'string' && rule.hex.length <= 2 * 1024 * 1024 && /^(?:[0-9a-fA-F]{2}|\?\?)(?:\s+(?:[0-9a-fA-F]{2}|\?\?))*$/.test(rule.hex.trim());
    if (validLiteral === validHex) throw new Error('Definition must contain exactly one valid literalBase64 or YARA-compatible hex string');
  }
  return definitions;
}

export function verifySignedDefinitionEnvelope(envelope, { publicKeys, minimumVersion = 0 } = {}) {
  if (!envelope || typeof envelope !== 'object') throw new Error('Definition envelope is invalid');
  if (typeof envelope.payloadBase64 !== 'string' || !isCanonicalBase64(envelope.payloadBase64)) throw new Error('Definition payload is invalid');
  if (typeof envelope.signatureBase64 !== 'string' || !isCanonicalBase64(envelope.signatureBase64)) throw new Error('Definition signature is invalid');
  const key = publicKeys?.[envelope.keyId];
  if (typeof key !== 'string') throw new Error('Definition signing key is not trusted');
  const payload = Buffer.from(envelope.payloadBase64, 'base64');
  const signature = Buffer.from(envelope.signatureBase64, 'base64');
  if (!crypto.verify(null, payload, key, signature)) throw new Error('Definition signature verification failed');
  let parsed;
  try { parsed = JSON.parse(payload.toString('utf8')); }
  catch { throw new Error('Definition payload is not valid JSON'); }
  validateDefinitions(parsed);
  if (parsed.version < minimumVersion) throw new Error('Definition rollback was rejected');
  return parsed;
}

function validateHashMap(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length > 1_000_000) throw new Error(`${label} map is invalid`);
  for (const [hash, description] of Object.entries(value)) {
    if (!/^[0-9a-f]{64}$/i.test(hash)) throw new Error(`${label} hash is invalid`);
    const values = Array.isArray(description) ? description : [description];
    if (!values.length || values.length > 8 || values.some(item => typeof item !== 'string' || item.length > 500)) throw new Error(`${label} description is invalid`);
  }
}

function isCanonicalBase64(value) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  try { return Buffer.from(value, 'base64').toString('base64') === value; }
  catch { return false; }
}
