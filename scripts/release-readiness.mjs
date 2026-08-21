import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { inspectReleaseReadiness } from '../src/release-readiness.mjs';

const args = parseArgs(process.argv.slice(2));
const root = path.resolve(args.root ?? '.');
const packageInfo = await readJson(path.join(root, 'package.json'));
const lockInfo = await readJson(path.join(root, 'package-lock.json'));
const feedConfig = await readJson(path.join(root, 'config', 'definition-feed.json'));
const keysConfig = await readJson(path.join(root, 'config', 'definition-keys.json'));
const workflowExists = await exists(path.join(root, '.github', 'workflows', 'definitions-feed.yml'));
const report = await inspectReleaseReadiness({ rootDirectory: root, packageInfo, lockInfo, feedConfig, keysConfig, workflowExists });
const output = path.resolve(args.output ?? path.join('dist', 'release-readiness.json'));
await writeAtomic(output, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ ...report, output }, null, 2));
if (args.strict === true && report.status !== 'ready') process.exitCode = 1;

async function readJson(file) { return JSON.parse(await fsp.readFile(file, 'utf8')); }
async function exists(file) { try { await fsp.access(file); return true; } catch { return false; } }
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
function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index++) {
    const value = values[index];
    if (!value.startsWith('--')) throw new Error(`Argumento desconocido: ${value}`);
    const key = value.slice(2);
    if (key === 'strict') { result[key] = true; continue; }
    const next = values[index + 1];
    if (!next || next.startsWith('--')) throw new Error(`Falta valor para --${key}.`);
    result[key] = next;
    index++;
  }
  return result;
}
