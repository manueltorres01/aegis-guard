import fsp from 'node:fs/promises';
import path from 'node:path';

const PRIVATE_EXTENSIONS = new Set(['.pem', '.p12', '.pfx', '.key']);
const SKIPPED_DIRECTORIES = new Set(['.git', 'node_modules', 'dist', 'dist-0.10.0', 'dist-0.11.0', 'dist-0.12.0', 'coverage', '.npm-cache', '.tmp-threat-intel']);

/**
 * Performs local, deterministic release checks. It cannot inspect GitHub
 * secrets, certificate validity or an external provider account, so those
 * remain explicit warnings instead of being silently presented as ready.
 */
export async function inspectReleaseReadiness({
  rootDirectory,
  packageInfo,
  lockInfo,
  feedConfig,
  keysConfig,
  workflowExists,
  privateArtifacts
} = {}) {
  const checks = [];
  const packageVersion = typeof packageInfo?.version === 'string' ? packageInfo.version : '';
  const lockVersion = typeof lockInfo?.packages?.['']?.version === 'string' ? lockInfo.packages[''].version : typeof lockInfo?.version === 'string' ? lockInfo.version : '';
  addCheck(checks, 'package-version', packageVersion && /^\d+\.\d+\.\d+$/.test(packageVersion), packageVersion ? `package.json ${packageVersion}` : 'package.json no contiene una versión semántica.', 'error');
  addCheck(checks, 'lock-version', Boolean(packageVersion && packageVersion === lockVersion), `package-lock.json=${lockVersion || 'ausente'}; package.json=${packageVersion || 'ausente'}.`, 'error');
  addCheck(checks, 'feed-workflow', workflowExists === true, workflowExists ? 'Workflow diario encontrado.' : 'Falta .github/workflows/definitions-feed.yml.', 'error');

  const feedEnabled = feedConfig?.enabled === true;
  const feedUrl = typeof feedConfig?.url === 'string' ? feedConfig.url.trim() : '';
  const feedUrlValid = feedEnabled && isSafeHttpsUrl(feedUrl);
  addCheck(checks, 'feed-url', feedUrlValid, feedEnabled ? (feedUrlValid ? 'Feed habilitado con URL HTTPS.' : 'El feed habilitado no tiene una URL HTTPS válida.') : 'Feed remoto desactivado por seguridad hasta provisionar la clave pública.', feedEnabled ? 'error' : 'warning');

  const publicKeys = keysConfig?.keys && typeof keysConfig.keys === 'object' && !Array.isArray(keysConfig.keys) ? keysConfig.keys : {};
  const hasPublicKey = Object.keys(publicKeys).length > 0;
  addCheck(checks, 'definition-trust', feedEnabled && hasPublicKey, feedEnabled ? (hasPublicKey ? `${Object.keys(publicKeys).length} clave(s) pública(s) configurada(s).` : 'El feed está habilitado sin clave pública de confianza.') : 'La confianza Ed25519 todavía no está provisionada.', feedEnabled ? 'error' : 'warning');
  addCheck(checks, 'provider-secrets', false, 'La existencia de AEGIS_DEFINITION_PRIVATE_KEY y AEGIS_ABUSECH_AUTH_KEY solo puede comprobarse en GitHub Actions.', 'warning');

  const artifacts = Array.isArray(privateArtifacts) ? privateArtifacts : rootDirectory ? await findPrivateArtifacts(path.resolve(rootDirectory)) : [];
  addCheck(checks, 'private-artifacts', artifacts.length === 0, artifacts.length ? `Hay material privado dentro del árbol: ${artifacts.join(', ')}` : 'No se encontraron PEM/P12/PFX/KEY en las carpetas del proyecto.', 'error');

  const errors = checks.filter(check => check.status === 'error').length;
  const warnings = checks.filter(check => check.status === 'warning').length;
  return {
    schemaVersion: 1,
    status: errors ? 'blocked' : warnings ? 'ready-with-warnings' : 'ready',
    packageVersion: packageVersion || null,
    checkedAt: new Date().toISOString(),
    summary: { total: checks.length, errors, warnings, passed: checks.filter(check => check.status === 'passed').length },
    checks
  };
}

async function findPrivateArtifacts(rootDirectory) {
  const found = [];
  await walk(rootDirectory, rootDirectory, found);
  return found.slice(0, 32);
}

async function walk(root, current, found) {
  if (found.length >= 32) return;
  let entries;
  try { entries = await fsp.readdir(current, { withFileTypes: true }); }
  catch { return; }
  for (const entry of entries) {
    if (found.length >= 32) return;
    if (entry.isDirectory() && SKIPPED_DIRECTORIES.has(entry.name)) continue;
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) await walk(root, absolute, found);
    else if (entry.isFile() && PRIVATE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) found.push(path.relative(root, absolute).replaceAll('\\', '/'));
  }
}

function addCheck(checks, id, passed, message, failureSeverity) {
  checks.push({ id, status: passed ? 'passed' : failureSeverity, message: String(message).slice(0, 500) });
}

function isSafeHttpsUrl(value) {
  if (!value || value.length > 2_000) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port && !['localhost', '127.0.0.1', '::1'].includes(url.hostname.toLowerCase());
  } catch { return false; }
}
