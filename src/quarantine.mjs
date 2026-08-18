import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathExists, resolveInside } from './util.mjs';
import { normalizeInternalPath, quarantineStagingName, restoreStagingName } from './internal-paths.mjs';

const STREAM_CHUNK_BYTES = 1024 * 1024;
const MAX_LIST_ITEMS = 5_000;
const MAX_LIST_BYTES = 8 * 1024 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HARD_LINK_UNSUPPORTED = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'EXDEV']);

export class Quarantine {
  constructor(directory, { key, removeStaged = file => fs.unlink(file) } = {}) {
    this.directory = path.resolve(directory);
    if (typeof removeStaged !== 'function') throw new TypeError('removeStaged must be a function');
    this.removeStaged = removeStaged;
    this.transientPaths = new Set();
    if (key !== undefined) {
      const material = Buffer.from(key);
      if (material.length !== 32) throw new Error('Quarantine key must contain exactly 32 bytes');
      this.providedKey = Buffer.from(material);
    }
  }

  async init() {
    await fs.mkdir(this.directory, { recursive: true });
    if (this.providedKey) {
      this.key = this.providedKey;
      return;
    }
    const keyFile = path.join(this.directory, '.key');
    if (!await pathExists(keyFile)) await fs.writeFile(keyFile, crypto.randomBytes(32), { mode: 0o600, flag: 'wx' });
    this.key = await fs.readFile(keyFile);
  }

  isTransientPath(candidate) {
    return this.transientPaths.has(normalizeInternalPath(candidate));
  }

  async isolate(file, scan, { signal } = {}) {
    await this.init();
    signal?.throwIfAborted();
    const source = path.resolve(file);
    const id = crypto.randomUUID();
    const stagedSource = path.join(path.dirname(source), quarantineStagingName(id));
    const binFile = resolveInside(this.directory, `${id}.bin`);
    const metaFile = resolveInside(this.directory, `${id}.json`);
    const temporaryBin = resolveInside(this.directory, `${id}.bin.tmp`);
    const temporaryMeta = resolveInside(this.directory, `${id}.json.tmp`);
    const transientKey = normalizeInternalPath(stagedSource);
    this.transientPaths.add(transientKey);
    try {
      signal?.throwIfAborted();
      await fs.rename(source, stagedSource);
    }
    catch (error) { this.transientPaths.delete(transientKey); throw error; }
    let committedBin = false;
    let committedMeta = false;
    let storedMetadata;
    try {
      const metadata = {
        format: 2,
        id,
        originalPath: source,
        quarantinedAt: new Date().toISOString(),
        sha256: scan.sha256,
        verdict: scan.verdict,
        score: scan.score,
        findings: scan.findings
      };
      const aad = authenticatedMetadata(metadata);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
      cipher.setAAD(aad);
      const actualHash = await encryptFile(stagedSource, temporaryBin, cipher, { signal });
      if (!scan.sha256 || actualHash !== scan.sha256) {
        throw new Error('File changed after scanning; refusing to quarantine it');
      }
      signal?.throwIfAborted();
      storedMetadata = {
        ...metadata,
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64')
      };
      await fs.writeFile(temporaryMeta, JSON.stringify(storedMetadata, null, 2), { flag: 'wx', mode: 0o600 });
      signal?.throwIfAborted();
      await fs.rename(temporaryBin, binFile);
      committedBin = true;
      signal?.throwIfAborted();
      await fs.rename(temporaryMeta, metaFile);
      committedMeta = true;
      signal?.throwIfAborted();
      await this.removeStaged(stagedSource);
      if (await pathExists(stagedSource)) throw new Error('Unable to remove staged quarantine source');
      return storedMetadata;
    } catch (error) {
      const stagedExists = await pathExists(stagedSource);
      if (committedMeta && !stagedExists) return storedMetadata;
      await Promise.allSettled([
        fs.rm(temporaryBin, { force: true }),
        fs.rm(temporaryMeta, { force: true }),
        committedBin ? fs.rm(binFile, { force: true }) : Promise.resolve(),
        committedMeta ? fs.rm(metaFile, { force: true }) : Promise.resolve()
      ]);
      if (stagedExists) {
        if (!await pathExists(source)) await fs.rename(stagedSource, source);
        else {
          const recovery = `${source}.aegis-recovered-${id}`;
          await fs.rename(stagedSource, recovery);
          error.message += `; original preserved at ${recovery}`;
        }
      }
      throw error;
    } finally {
      this.transientPaths.delete(transientKey);
    }
  }

  async list({ limit = MAX_LIST_ITEMS, maxBytes = MAX_LIST_BYTES } = {}) {
    await this.init();
    const maximum = Number.isSafeInteger(limit) ? Math.max(0, Math.min(limit, MAX_LIST_ITEMS)) : MAX_LIST_ITEMS;
    const byteBudget = Number.isSafeInteger(maxBytes) ? Math.max(0, Math.min(maxBytes, MAX_LIST_BYTES)) : MAX_LIST_BYTES;
    let retainedBytes = 0;
    const inventory = {
      items: [],
      total: 0,
      truncatedCount: 0,
      corruptCount: 0,
      oversizedCount: 0
    };
    const directory = await fs.opendir(this.directory);
    for await (const entry of directory) {
      const match = entry.name.match(/^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json$/i);
      if (!match) continue;
      const id = match[1].toLowerCase();
      try {
        const { metadata, bytesRead } = await readBoundedMetadata(resolveInside(this.directory, entry.name));
        if (!isValidMetadata(metadata, id)) throw new Error('Invalid quarantine metadata');
        const payloadStat = await fs.lstat(resolveInside(this.directory, `${id}.bin`));
        if (payloadStat.isSymbolicLink() || !payloadStat.isFile()) throw new Error('Invalid quarantine payload');
        inventory.total++;
        if (inventory.items.length < maximum && retainedBytes + bytesRead <= byteBudget) {
          inventory.items.push(metadata);
          retainedBytes += bytesRead;
        }
      } catch (error) {
        if (error.code === 'METADATA_TOO_LARGE') inventory.oversizedCount++;
        else inventory.corruptCount++;
      }
    }
    inventory.truncatedCount = Math.max(0, inventory.total - inventory.items.length);
    return inventory;
  }

  async restore(id, destination) {
    await this.init();
    if (!UUID.test(id)) throw new Error('Invalid quarantine identifier');
    const normalizedId = String(id).toLowerCase();
    const metaFile = resolveInside(this.directory, `${normalizedId}.json`);
    const binFile = resolveInside(this.directory, `${normalizedId}.bin`);
    const { metadata } = await readBoundedMetadata(metaFile);
    if (!isValidMetadata(metadata, normalizedId)) throw new Error('Invalid quarantine metadata');
    const target = path.resolve(destination ?? metadata.originalPath);
    if (await pathExists(target)) throw new Error(`Refusing to overwrite existing file: ${target}`);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(metadata.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(metadata.tag, 'base64'));
    if (metadata.format === 2) decipher.setAAD(authenticatedMetadata(metadata));
    await fs.mkdir(path.dirname(target), { recursive: true });
    const temporaryRestore = path.join(
      path.dirname(target),
      restoreStagingName(normalizedId, crypto.randomUUID())
    );
    const transientKey = normalizeInternalPath(temporaryRestore);
    this.transientPaths.add(transientKey);
    try {
      const actual = await decryptFile(binFile, temporaryRestore, decipher);
      if (actual !== metadata.sha256) throw new Error('Quarantine integrity check failed');
      await publishVerifiedFile(temporaryRestore, target, metadata.sha256);
    } catch (error) {
      await fs.rm(temporaryRestore, { force: true }).catch(() => {});
      throw error;
    } finally {
      this.transientPaths.delete(transientKey);
    }
    await fs.unlink(binFile);
    await fs.unlink(metaFile);
    return target;
  }
}

async function readBoundedMetadata(file) {
  const before = await fs.lstat(file);
  if (before.isSymbolicLink() || !before.isFile()) throw new Error('Invalid quarantine metadata file');
  if (before.size > MAX_METADATA_BYTES) throw metadataTooLargeError();

  const handle = await fs.open(file, 'r');
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || identityChanged(before, opened)) throw new Error('Quarantine metadata changed while reading');
    if (opened.size > MAX_METADATA_BYTES) throw metadataTooLargeError();

    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) throw new Error('Truncated quarantine metadata');
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (identityChanged(opened, after) || metadataChanged(opened, after)) {
      throw new Error('Quarantine metadata changed while reading');
    }
    return { metadata: JSON.parse(bytes.toString('utf8')), bytesRead: bytes.length };
  } finally {
    await handle.close();
  }
}

function metadataTooLargeError() {
  const error = new Error('Quarantine metadata exceeds the safe size limit');
  error.code = 'METADATA_TOO_LARGE';
  return error;
}

function isValidMetadata(metadata, expectedId) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return false;
  // Pre-format metadata is the legacy AES-GCM layout (equivalent to format 1).
  if (metadata.format !== undefined && metadata.format !== 1 && metadata.format !== 2) return false;
  if (typeof metadata.id !== 'string' || metadata.id.toLowerCase() !== expectedId) return false;
  if (typeof metadata.originalPath !== 'string' || !path.isAbsolute(metadata.originalPath)) return false;
  if (metadata.originalPath.length === 0 || metadata.originalPath.length > 32_768 || metadata.originalPath.includes('\0')) return false;
  if (typeof metadata.quarantinedAt !== 'string' || !Number.isFinite(Date.parse(metadata.quarantinedAt))) return false;
  if (typeof metadata.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(metadata.sha256)) return false;
  if (!['suspicious', 'malicious'].includes(metadata.verdict)) return false;
  if (!Number.isFinite(metadata.score) || metadata.score < 0 || metadata.score > 100) return false;
  if (!Array.isArray(metadata.findings) || metadata.findings.length > 1_000) return false;
  if (!metadata.findings.every(isValidFinding)) return false;
  return isExactBase64(metadata.iv, 12) && isExactBase64(metadata.tag, 16);
}

function isValidFinding(finding) {
  return Boolean(
    finding
    && typeof finding === 'object'
    && !Array.isArray(finding)
    && typeof finding.id === 'string'
    && finding.id.length <= 256
    && typeof finding.description === 'string'
    && finding.description.length <= 4_096
    && Number.isFinite(finding.score)
    && finding.score >= 0
    && finding.score <= 100
  );
}

function isExactBase64(value, expectedBytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === expectedBytes && decoded.toString('base64') === value;
}

async function encryptFile(source, destination, cipher, { signal } = {}) {
  signal?.throwIfAborted();
  const sourceStat = await fs.lstat(source);
  if (sourceStat.isSymbolicLink() || !sourceStat.isFile()) throw new Error('Quarantine source is not a regular file');
  const input = await fs.open(source, 'r');
  let output;
  try {
    const openedStat = await input.stat();
    if (!openedStat.isFile() || identityChanged(sourceStat, openedStat)) {
      throw new Error('File changed after scanning; refusing to quarantine it');
    }
    output = await fs.open(destination, 'wx', 0o600);
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(STREAM_CHUNK_BYTES);
    let position = 0;
    while (position < openedStat.size) {
      signal?.throwIfAborted();
      const requested = Math.min(buffer.length, openedStat.size - position);
      const { bytesRead } = await input.read(buffer, 0, requested, position);
      if (bytesRead === 0) throw new Error('File changed after scanning; refusing to quarantine it');
      const clear = buffer.subarray(0, bytesRead);
      hash.update(clear);
      await writeAll(output, cipher.update(clear));
      position += bytesRead;
    }
    const finalStat = await input.stat();
    if (identityChanged(openedStat, finalStat) || metadataChanged(openedStat, finalStat)) {
      throw new Error('File changed after scanning; refusing to quarantine it');
    }
    signal?.throwIfAborted();
    await writeAll(output, cipher.final());
    await output.sync();
    return hash.digest('hex');
  } finally {
    await Promise.allSettled([input.close(), output?.close()]);
  }
}

async function decryptFile(source, destination, decipher) {
  const sourceStat = await fs.lstat(source);
  if (sourceStat.isSymbolicLink() || !sourceStat.isFile()) throw new Error('Invalid quarantine payload');
  const input = await fs.open(source, 'r');
  let output;
  try {
    const openedStat = await input.stat();
    if (!openedStat.isFile() || identityChanged(sourceStat, openedStat)) throw new Error('Invalid quarantine payload');
    output = await fs.open(destination, 'wx', 0o600);
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(STREAM_CHUNK_BYTES);
    let position = 0;
    while (position < openedStat.size) {
      const requested = Math.min(buffer.length, openedStat.size - position);
      const { bytesRead } = await input.read(buffer, 0, requested, position);
      if (bytesRead === 0) throw new Error('Invalid quarantine payload');
      const clear = decipher.update(buffer.subarray(0, bytesRead));
      hash.update(clear);
      await writeAll(output, clear);
      position += bytesRead;
    }
    const finalStat = await input.stat();
    if (identityChanged(openedStat, finalStat) || metadataChanged(openedStat, finalStat)) {
      throw new Error('Invalid quarantine payload');
    }
    const final = decipher.final();
    hash.update(final);
    await writeAll(output, final);
    await output.sync();
    return hash.digest('hex');
  } finally {
    await Promise.allSettled([input.close(), output?.close()]);
  }
}

async function writeAll(handle, data) {
  let offset = 0;
  while (offset < data.length) {
    const { bytesWritten } = await handle.write(data, offset, data.length - offset, null);
    if (bytesWritten === 0) throw new Error('Unable to write quarantine data');
    offset += bytesWritten;
  }
}

async function publishVerifiedFile(source, target, expectedHash) {
  let linked = false;
  try {
    await fs.link(source, target);
    linked = true;
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error(`Refusing to overwrite existing file: ${target}`);
    if (!HARD_LINK_UNSUPPORTED.has(error.code)) throw error;
  }
  if (linked) {
    await fs.rm(source, { force: true });
    return;
  }

  // Filesystems such as FAT/exFAT can reject hard links. `wx` still reserves
  // the destination without an overwrite race; failed copies are removed.
  const input = await fs.open(source, 'r');
  let output;
  let destinationCreated = false;
  try {
    const sourceStat = await input.stat();
    try { output = await fs.open(target, 'wx', 0o600); }
    catch (error) {
      if (error.code === 'EEXIST') throw new Error(`Refusing to overwrite existing file: ${target}`);
      throw error;
    }
    destinationCreated = true;
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(STREAM_CHUNK_BYTES);
    let position = 0;
    while (position < sourceStat.size) {
      const requested = Math.min(buffer.length, sourceStat.size - position);
      const { bytesRead } = await input.read(buffer, 0, requested, position);
      if (bytesRead === 0) throw new Error('Verified restore file changed before publication');
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      await writeAll(output, chunk);
      position += bytesRead;
    }
    const finalStat = await input.stat();
    if (metadataChanged(sourceStat, finalStat) || hash.digest('hex') !== expectedHash) {
      throw new Error('Verified restore file changed before publication');
    }
    await output.sync();
  } catch (error) {
    await Promise.allSettled([input.close(), output?.close()]);
    if (destinationCreated) await fs.rm(target, { force: true }).catch(() => {});
    throw error;
  }
  await Promise.allSettled([input.close(), output?.close()]);
  await fs.rm(source, { force: true });
}

function identityChanged(before, after) {
  if (before.dev && after.dev && before.dev !== after.dev) return true;
  return Boolean(before.ino && after.ino && before.ino !== after.ino);
}

function metadataChanged(before, after) {
  return before.size !== after.size || before.mtimeMs !== after.mtimeMs;
}

function authenticatedMetadata(metadata) {
  return Buffer.from(JSON.stringify({
    format: metadata.format,
    id: metadata.id,
    originalPath: metadata.originalPath,
    quarantinedAt: metadata.quarantinedAt,
    sha256: metadata.sha256,
    verdict: metadata.verdict,
    score: metadata.score,
    findings: metadata.findings
  }));
}
