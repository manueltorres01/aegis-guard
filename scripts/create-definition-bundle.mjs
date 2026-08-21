import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { validateDefinitions } from '../src/definition-security.mjs';

const args = parseArgs(process.argv.slice(2));
const input = path.resolve(args.input ?? 'definitions/signatures.json');
const output = path.resolve(args.output ?? 'dist/definitions.bundle.json');
const keyId = args['key-id'];
if (!keyId || !/^[A-Za-z0-9._-]{1,80}$/.test(keyId)) throw new Error('Uso: --key-id <id> --private-key <pem> [--input <json>] [--output <json>]');
if (!args['private-key']) throw new Error('Falta --private-key <pem>');

const definitions = validateDefinitions(JSON.parse(await fsp.readFile(input, 'utf8')));
const privateKey = crypto.createPrivateKey(await fsp.readFile(path.resolve(args['private-key'])));
if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('La clave de definiciones debe ser Ed25519');
const payload = Buffer.from(JSON.stringify(definitions));
const envelope = {
  schemaVersion: 1,
  keyId,
  payloadBase64: payload.toString('base64'),
  signatureBase64: crypto.sign(null, payload, privateKey).toString('base64')
};
await fsp.mkdir(path.dirname(output), { recursive: true });
await fsp.writeFile(output, `${JSON.stringify(envelope, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
console.log(`Wrote signed definition bundle v${definitions.version} to ${output}`);

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
