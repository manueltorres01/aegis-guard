import fs from 'node:fs/promises';
import path from 'node:path';
import { createIntegrityManifest } from '../src/self-protection-audit.mjs';

const root = path.resolve(process.cwd());
const target = path.join(root, 'definitions', 'integrity-manifest.json');
const manifest = await createIntegrityManifest(root);
await fs.mkdir(path.dirname(target), { recursive: true });
await fs.writeFile(target, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'w', mode: 0o600 });
console.log(`Wrote ${manifest.files.length} integrity entries to ${target}`);
