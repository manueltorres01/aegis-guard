#!/usr/bin/env node
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fsp from 'node:fs/promises';
import { ThreatIntelStore } from '../src/threat-intel-store.mjs';

const baseDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const [sha256, ...flags] = process.argv.slice(2);
if (!/^[0-9a-f]{64}$/i.test(String(sha256 ?? '').trim())) {
  console.error('Uso: npm run intel:lookup -- <sha256> [--offline] [--force]');
  process.exitCode = 1;
} else {
  const config = await readJsonOr(path.join(baseDirectory, 'config', 'threat-intel.json'), {});
  const store = new ThreatIntelStore({
    dataDirectory: process.env.AEGIS_DATA_DIRECTORY || (process.env.APPDATA ? path.join(process.env.APPDATA, 'aegis-guard') : path.join(os.homedir(), '.aegis-guard')),
    config
  });
  await store.init();
  const result = await store.lookupSha256(sha256, { allowNetwork: !flags.includes('--offline'), force: flags.includes('--force') });
  console.log(JSON.stringify(result, null, 2));
  if (result.verdict === 'known-malicious') process.exitCode = 2;
}

async function readJsonOr(file, fallback) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); }
  catch (error) { return error?.code === 'ENOENT' || error?.name === 'SyntaxError' ? fallback : (() => { throw error; })(); }
}
