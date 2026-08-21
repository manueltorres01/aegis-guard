import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { validateDefinitions, verifySignedDefinitionEnvelope } from '../src/definition-security.mjs';
import {
  buildThreatIntelDefinitions,
  createSignedDefinitionEnvelope,
  fetchMalwareBazaar,
  fetchThreatFox
} from '../src/threat-intel-feed-builder.mjs';

const args = parseArgs(process.argv.slice(2));
const basePath = path.resolve(args.base ?? 'definitions/signatures.json');
const outputPath = path.resolve(args.output ?? 'feeds/definitions.bundle.json');
const previousPath = path.resolve(args.previous ?? outputPath);
const keysPath = path.resolve(args.keys ?? 'config/definition-keys.json');
const privateKeyPath = requiredPath(args['private-key'], '--private-key');
const keyId = requiredPath(args['key-id'] ?? process.env.AEGIS_DEFINITION_KEY_ID, '--key-id');
const authKey = typeof (args['auth-key'] ?? process.env.AEGIS_ABUSECH_AUTH_KEY) === 'string'
  ? (args['auth-key'] ?? process.env.AEGIS_ABUSECH_AUTH_KEY).trim()
  : '';
const generatedAt = args['generated-at'] ?? new Date().toISOString();
const offline = args.offline === true;

if (!offline && !authKey) throw new Error('Falta un Auth-Key de abuse.ch. Usa --auth-key o AEGIS_ABUSECH_AUTH_KEY.');

const baseDefinitions = validateDefinitions(JSON.parse(await fsp.readFile(basePath, 'utf8')));
const previousDefinitions = await readPreviousDefinitions(previousPath, keysPath);
const sourceStatus = {};
let malwareBazaarPayload = null;
let threatFoxPayload = null;

if (!offline) {
  const [malwareBazaarResult, threatFoxResult] = await Promise.allSettled([
    fetchMalwareBazaar({ authKey, hours: args['mb-hours'] ?? 168 }),
    fetchThreatFox({ authKey, days: args['tf-days'] ?? 7 })
  ]);
  [
    ['malwarebazaar', malwareBazaarResult],
    ['threatfox', threatFoxResult]
  ].forEach(([provider, result]) => {
    if (result.status === 'fulfilled') {
      const records = Array.isArray(result.value?.data) ? result.value.data.length : 0;
      sourceStatus[provider] = { status: 'ok', records, queriedAt: generatedAt };
      if (provider === 'malwarebazaar') malwareBazaarPayload = result.value;
      else threatFoxPayload = result.value;
    } else {
      sourceStatus[provider] = { status: 'error', records: 0, queriedAt: generatedAt, error: clampText(result.reason?.message, 240) || 'Consulta fallida.' };
      console.warn(`[${provider}] ${sourceStatus[provider].error}`);
    }
  });
  if (!malwareBazaarPayload && !threatFoxPayload) throw new Error('No se pudo consultar ninguna fuente; se conserva el feed anterior sin publicar una versión vacía.');
} else {
  sourceStatus.malwarebazaar = { status: 'not-configured', records: 0, queriedAt: generatedAt, error: null };
  sourceStatus.threatfox = { status: 'not-configured', records: 0, queriedAt: generatedAt, error: null };
}

const definitions = buildThreatIntelDefinitions({
  baseDefinitions,
  previousDefinitions,
  malwareBazaarPayload,
  threatFoxPayload,
  sourceStatus,
  generatedAt,
  version: args.version ? Number(args.version) : undefined,
  retentionDays: args['retention-days'] ? Number(args['retention-days']) : undefined
});
const privateKey = await fsp.readFile(path.resolve(privateKeyPath), 'utf8');
const envelope = createSignedDefinitionEnvelope(definitions, { keyId, privateKey });
await writeAtomic(outputPath, `${JSON.stringify(envelope, null, 2)}\n`);

console.log(JSON.stringify({
  output: outputPath,
  version: definitions.version,
  generatedAt: definitions.generatedAt,
  threatIntelEntries: Object.keys(definitions.threatIntel?.entries ?? {}).length,
  sources: sourceStatus,
  offline
}, null, 2));

async function readPreviousDefinitions(file, publicKeysFile) {
  let envelope;
  try { envelope = JSON.parse(await fsp.readFile(file, 'utf8')); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  const publicKeys = await readPublicKeys(publicKeysFile);
  if (Object.keys(publicKeys).length) return verifySignedDefinitionEnvelope(envelope, { publicKeys });
  if (typeof envelope?.payloadBase64 !== 'string') throw new Error('El feed anterior no contiene un payload firmado válido.');
  const payload = Buffer.from(envelope.payloadBase64, 'base64').toString('utf8');
  return validateDefinitions(JSON.parse(payload));
}

async function readPublicKeys(file) {
  try {
    const value = JSON.parse(await fsp.readFile(file, 'utf8'));
    return value?.keys && typeof value.keys === 'object' && !Array.isArray(value.keys) ? value.keys : {};
  } catch (error) {
    if (error?.code === 'ENOENT') return {};
    throw error;
  }
}

async function writeAtomic(file, contents) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {
    await fsp.writeFile(temporary, contents, { flag: 'wx', mode: 0o600 });
    await fsp.rm(file, { force: true });
    await fsp.rename(temporary, file);
  } catch (error) {
    await fsp.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

function requiredPath(value, label) {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > 32_767) throw new Error(`Falta ${label}.`);
  return value;
}

function clampText(value, maximum) { return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maximum) : ''; }

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index++) {
    const value = values[index];
    if (!value.startsWith('--')) throw new Error(`Argumento desconocido: ${value}`);
    const key = value.slice(2);
    if (key === 'offline') { result[key] = true; continue; }
    const next = values[index + 1];
    if (!next || next.startsWith('--')) throw new Error(`Falta valor para --${key}.`);
    result[key] = next;
    index++;
  }
  return result;
}
