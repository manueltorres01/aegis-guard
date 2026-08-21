import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';

const args = parseArgs(process.argv.slice(2));
const root = path.resolve(args.root ?? '.');
const lockPath = path.join(root, 'package-lock.json');
const lockText = await fsp.readFile(lockPath, 'utf8');
const lock = JSON.parse(lockText);
if (lock.lockfileVersion !== 3) throw new Error('El SBOM requiere package-lock.json lockfileVersion 3.');
const rootPackage = lock.packages?.[''];
if (!rootPackage?.name || !rootPackage?.version) throw new Error('El package-lock no contiene el paquete raíz.');

const packageRecords = Object.entries(lock.packages).filter(([key, value]) => key && value && typeof value === 'object' && typeof value.version === 'string');
const packageIds = new Map();
const packages = [{
  SPDXID: 'SPDXRef-Package-root',
  name: rootPackage.name,
  versionInfo: rootPackage.version,
  downloadLocation: 'NOASSERTION',
  licenseConcluded: rootPackage.license ?? 'NOASSERTION',
  licenseDeclared: rootPackage.license ?? 'NOASSERTION',
  filesAnalyzed: false,
  supplier: 'NOASSERTION',
  copyrightText: 'NOASSERTION'
}];

for (const [key, info] of packageRecords) {
  const name = packageName(key);
  const id = `SPDXRef-Package-${safeId(name)}-${crypto.createHash('sha1').update(key).digest('hex').slice(0, 12)}`;
  packageIds.set(name, packageIds.get(name) ?? id);
  const checksum = parseIntegrity(info.integrity);
  packages.push({
    SPDXID: id,
    name,
    versionInfo: info.version,
    downloadLocation: typeof info.resolved === 'string' ? info.resolved : 'NOASSERTION',
    licenseConcluded: typeof info.license === 'string' ? info.license : 'NOASSERTION',
    licenseDeclared: typeof info.license === 'string' ? info.license : 'NOASSERTION',
    filesAnalyzed: false,
    supplier: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    ...(checksum ? { checksums: [checksum] } : {}),
    externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: `pkg:npm/${name}@${info.version}` }]
  });
}

const relationships = [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Package-root' }];
for (const dependencyName of Object.keys({ ...rootPackage.dependencies, ...rootPackage.devDependencies, ...rootPackage.optionalDependencies })) {
  const id = packageIds.get(dependencyName);
  if (id) relationships.push({ spdxElementId: 'SPDXRef-Package-root', relationshipType: 'DEPENDS_ON', relatedSpdxElement: id });
}

const lockDigest = crypto.createHash('sha256').update(lockText).digest('hex');
const sourceDate = Number(process.env.SOURCE_DATE_EPOCH);
const created = Number.isSafeInteger(sourceDate) && sourceDate >= 0 ? new Date(sourceDate * 1_000).toISOString() : new Date().toISOString();
const document = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `${rootPackage.name}-${rootPackage.version}-sbom`,
  documentNamespace: `https://github.com/manueltorres01/aegis-guard/sbom/${rootPackage.version}/${lockDigest}`,
  creationInfo: { created, creators: ['Tool: aegis-guard-sbom'] },
  documentDescribes: ['SPDXRef-Package-root'],
  packages,
  relationships,
  comment: 'Generated from the locked npm dependency graph. It does not assert that a dependency is vulnerability-free.'
};

const output = path.resolve(args.output ?? path.join('dist', `${rootPackage.name}-${rootPackage.version}.spdx.json`));
await fsp.mkdir(path.dirname(output), { recursive: true });
await fsp.writeFile(output, `${JSON.stringify(document, null, 2)}\n`, { flag: 'w', mode: 0o600 });
console.log(JSON.stringify({ output, packages: packages.length, relationships: relationships.length, lockSha256: lockDigest, created }, null, 2));

function packageName(key) {
  const normalized = key.replace(/^node_modules\//, '');
  const parts = normalized.split('/node_modules/');
  const tail = parts[parts.length - 1].split('/');
  return tail[0].startsWith('@') ? `${tail[0]}/${tail[1] ?? ''}` : tail[0];
}
function safeId(value) { return String(value).replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '') || 'package'; }
function parseIntegrity(value) {
  if (typeof value !== 'string') return null;
  const match = /^sha512-([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match) return null;
  return { algorithm: 'SHA512', checksumValue: Buffer.from(match[1], 'base64').toString('hex') };
}
function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index++) {
    const value = values[index];
    if (!value.startsWith('--')) throw new Error(`Argumento desconocido: ${value}`);
    const key = value.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith('--')) throw new Error(`Falta valor para --${key}.`);
    result[key] = next;
    index++;
  }
  return result;
}
