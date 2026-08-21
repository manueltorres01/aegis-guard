import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';

const args = parseArgs(process.argv.slice(2));
const keyId = args['key-id'];
const privateKeyPath = requiredPath(args['private-key'], '--private-key');
const publicConfigPath = requiredPath(args['public-config'], '--public-config');

if (!keyId || !/^[A-Za-z0-9._-]{1,80}$/.test(keyId)) {
  throw new Error('Uso: --key-id <id> --private-key <pem> --public-config <json>');
}

const privatePath = path.resolve(privateKeyPath);
const configPath = path.resolve(publicConfigPath);
if (privatePath === configPath) throw new Error('La clave privada y el fichero público deben ser distintos.');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
const publicConfig = await readPublicConfig(configPath, keyId, publicPem);

await fsp.mkdir(path.dirname(privatePath), { recursive: true });
await fsp.mkdir(path.dirname(configPath), { recursive: true });
await writeNew(privatePath, privatePem, 0o600);
try {
  await fsp.writeFile(configPath, `${JSON.stringify(publicConfig, null, 2)}\n`, { mode: 0o600 });
} catch (error) {
  await fsp.rm(privatePath, { force: true }).catch(() => {});
  throw error;
}

console.log(`Clave Ed25519 privada creada en ${privatePath}`);
console.log(`Clave pública de confianza creada en ${configPath} (keyId: ${keyId})`);
console.log('No subas la clave privada al repositorio ni la incluyas en el instalador.');

function requiredPath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 32_767) throw new Error(`Falta ${label}`);
  return value;
}

async function writeNew(file, contents, mode) {
  await fsp.writeFile(file, contents, { flag: 'wx', mode });
}

async function readPublicConfig(file, id, pem) {
  let existing = {};
  try {
    existing = JSON.parse(await fsp.readFile(file, 'utf8'));
  } catch (error) {
    if (error?.code !== 'ENOENT') throw new Error(`El fichero público no contiene JSON válido: ${file}`);
  }
  const keys = existing?.keys && typeof existing.keys === 'object' && !Array.isArray(existing.keys) ? { ...existing.keys } : {};
  if (Object.hasOwn(keys, id)) throw new Error(`Ya existe una clave pública con keyId «${id}».`);
  keys[id] = pem;
  return { schemaVersion: 1, keys };
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index++) {
    const value = values[index];
    if (!value.startsWith('--')) throw new Error(`Argumento desconocido: ${value}`);
    const key = value.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith('--')) throw new Error(`Falta valor para --${key}`);
    result[key] = next;
    index++;
  }
  return result;
}
