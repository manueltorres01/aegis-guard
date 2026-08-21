import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { analyzeStaticContent } from './static-analysis.mjs';

const EXECUTABLE = new Set(['.exe', '.dll', '.scr', '.com', '.msi', '.jar', '.ps1', '.vbs', '.js', '.jse', '.bat', '.cmd', '.hta']);
const SCRIPT = new Set(['.ps1', '.vbs', '.js', '.jse', '.bat', '.cmd', '.hta']);
const AUTHENTICODE = new Set(['.exe', '.dll', '.scr', '.com', '.msi']);
const LURE = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.jpeg', '.png', '.txt']);
const SCRIPT_RULES = [
  [/powershell(?:\.exe)?\s+[^\r\n]{0,160}-(?:enc|encodedcommand)\b/i, 35, 'Encoded PowerShell command'],
  [/(?:frombase64string|invoke-expression|\biex\b)/i, 18, 'Script obfuscation/execution primitive'],
  [/(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)/i, 55, 'Shadow-copy deletion'],
  [/(?:document_open|autoopen|workbook_open)/i, 20, 'Office auto-execution macro'],
  [/(?:rundll32|regsvr32|mshta)\.exe\s+(?:https?:|javascript:)/i, 40, 'Living-off-the-land remote execution']
];
const INJECTION_APIS = ['createremotethread', 'virtualallocex', 'writeprocessmemory'];
const TRUST_DISCOUNTABLE = new Set([
  'heuristic.entropy',
  'heuristic.pe-api-combination',
  'static.pe.rwx-section',
  'static.pe.writable-entry'
]);

const DEFAULT_STREAM_CHUNK_BYTES = 1024 * 1024;
const ENTROPY_SAMPLE_BYTES = 1024 * 1024;
const SCRIPT_OVERLAP_BYTES = 4 * 1024;
const STATIC_HEAD_BYTES = 8 * 1024 * 1024;
const STATIC_PROBE_BYTES = 64 * 1024;
const STATIC_TAIL_BYTES = 512 * 1024;
const DEFAULT_CACHE_MAX_ENTRIES = 512;
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const DEEP_STATIC_EXTENSIONS = new Set([
  ...AUTHENTICODE,
  ...SCRIPT,
  '.zip', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.jar', '.7z', '.rar'
]);
const TAIL_STATIC_EXTENSIONS = new Set(['.zip', '.docx', '.xlsx', '.pptx', '.jar']);

function entropy(buffer) {
  if (!buffer.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte]++;
  let result = 0;
  for (const count of counts) if (count) {
    const p = count / buffer.length;
    result -= p * Math.log2(p);
  }
  return result;
}

export class ScanEngine {
  constructor({
    definitions,
    threshold = 60,
    maxFileSizeMb = 128,
    exclude = [],
    excludePaths = [],
    trustVerifier = null,
    trustedPublisherOrganizations = [],
    trustedApplicationPolicies = [],
    isTransientPath = () => false,
    cacheMaxEntries = DEFAULT_CACHE_MAX_ENTRIES,
    cacheTtlMs = DEFAULT_CACHE_TTL_MS
  }) {
    if (typeof isTransientPath !== 'function') throw new TypeError('isTransientPath must be a function');
    this.definitions = definitions;
    this.threshold = threshold;
    this.maxBytes = maxFileSizeMb * 1024 * 1024;
    this.exclude = new Set(exclude.map(x => x.toLowerCase()));
    this.excludePaths = excludePaths.map(normalizePathKey);
    this.isTransientPath = isTransientPath;
    this.trustVerifier = typeof trustVerifier === 'function' ? trustVerifier : null;
    this.trustedPublisherOrganizations = new Set(trustedPublisherOrganizations.map(normalizePublisher));
    this.trustedApplicationPolicies = normalizeApplicationPolicies(trustedApplicationPolicies);
    this.cacheNamespace = this.computeCacheNamespace();
    this.cacheMaxEntries = clampInteger(cacheMaxEntries, 0, 4_096, DEFAULT_CACHE_MAX_ENTRIES);
    this.cacheTtlMs = clampInteger(cacheTtlMs, 0, 60 * 60 * 1000, DEFAULT_CACHE_TTL_MS);
    this.scanCache = new Map();
    this.performance = {
      fileScans: 0,
      cacheHits: 0,
      cacheMisses: 0,
      bytesRead: 0,
      peakWorkingBufferBytes: 0
    };
    this.patternRules = (definitions.patterns ?? []).map(rule => ({
      ...rule,
      ...compileDefinitionPattern(rule)
    })).filter(rule => rule.bytes.length > 0);
    this.patternOverlapBytes = Math.max(0, ...this.patternRules.map(rule => rule.bytes.length - 1));
  }

  replaceDefinitions(definitions) {
    if (!definitions || typeof definitions !== 'object' || !Number.isSafeInteger(definitions.version)) {
      throw new TypeError('Definitions are invalid');
    }
    this.definitions = definitions;
    this.patternRules = (definitions.patterns ?? []).map(rule => ({
      ...rule,
      ...compileDefinitionPattern(rule)
    })).filter(rule => rule.bytes.length > 0);
    this.patternOverlapBytes = Math.max(0, ...this.patternRules.map(rule => rule.bytes.length - 1));
    this.scanCache.clear();
    this.cacheNamespace = this.computeCacheNamespace();
    return { version: definitions.version, patterns: this.patternRules.length };
  }

  async scanFile(file, { signal, expectedIdentity } = {}) {
    return this.scanFileExhaustive(file, {
      signal,
      expectedIdentity,
      maximumBytes: this.maxBytes
    });
  }

  // Full and deep scans use this path for every file, including files larger
  // than maxBytes. The complete hash is calculated without retaining the file.
  async scanFileExhaustive(file, {
    signal,
    chunkSize = DEFAULT_STREAM_CHUNK_BYTES,
    expectedIdentity,
    maximumBytes = Number.POSITIVE_INFINITY
  } = {}) {
    signal?.throwIfAborted();
    const started = performance.now();
    const size = normalizeChunkSize(chunkSize);
    const firstStat = await fs.lstat(file);
    if (firstStat.isSymbolicLink() || !firstStat.isFile()) throw new Error('Not a regular file');
    if (expectedIdentity && snapshotChanged(expectedIdentity, firstStat)) throw new Error('File changed after discovery');

    this.performance.fileScans++;
    const cacheKey = this.createCacheKey(file, firstStat, maximumBytes);
    const cached = this.readCache(cacheKey);
    if (cached) {
      this.performance.cacheHits++;
      cached.durationMs = elapsed(started);
      return cached;
    }
    this.performance.cacheMisses++;

    const handle = await fs.open(file, 'r');
    try {
      const openedStat = await handle.stat();
      if (!openedStat.isFile() || identityChanged(firstStat, openedStat)) throw new Error('File changed before scanning');
      if (expectedIdentity && snapshotChanged(expectedIdentity, openedStat)) throw new Error('File changed after discovery');

      const result = createResult(file, openedStat.size);
      if (openedStat.size > maximumBytes) {
        result.verdict = 'skipped';
        result.findings.push({ id: 'limit.size', description: 'File exceeds configured scan size', score: 0 });
        result.durationMs = elapsed(started);
        return result;
      }
      const extension = path.extname(path.basename(file).toLowerCase());
      const executable = EXECUTABLE.has(extension);
      const script = SCRIPT.has(extension);
      const peLike = AUTHENTICODE.has(extension);
      const hash = crypto.createHash('sha256');
      const buffer = Buffer.allocUnsafe(Math.min(size, openedStat.size));
      const entropySample = executable
        ? Buffer.allocUnsafe(Math.min(openedStat.size, ENTROPY_SAMPLE_BYTES))
        : null;
      let staticHead = null;
      let staticHeadLength = 0;
      let staticTail = Buffer.alloc(0);
      let retainStaticTail = TAIL_STATIC_EXTENSIONS.has(extension);
      const matchedPatterns = new Set();
      const matchedScripts = new Set();
      const matchedInjectionApis = new Set();
      const overlapBytes = Math.max(this.patternOverlapBytes, executable ? SCRIPT_OVERLAP_BYTES : 0);
      let tail = Buffer.alloc(0);
      let position = 0;
      let entropyLength = 0;

      while (position < openedStat.size) {
        signal?.throwIfAborted();
        const requested = Math.min(buffer.length, openedStat.size - position);
        const { bytesRead } = await handle.read(buffer, 0, requested, position);
        if (bytesRead === 0) throw new Error('File changed during scanning');
        const chunk = buffer.subarray(0, bytesRead);
        this.performance.bytesRead += bytesRead;
        hash.update(chunk);

        if (!staticHead) {
          const deepStatic = DEEP_STATIC_EXTENSIONS.has(extension) || hasSupportedStaticMagic(chunk);
          staticHead = Buffer.allocUnsafe(Math.min(openedStat.size, deepStatic ? STATIC_HEAD_BYTES : STATIC_PROBE_BYTES));
          retainStaticTail ||= isZipMagic(chunk);
          this.performance.peakWorkingBufferBytes = Math.max(
            this.performance.peakWorkingBufferBytes,
            buffer.length + staticHead.length + (entropySample?.length ?? 0) + (retainStaticTail ? STATIC_TAIL_BYTES : 0)
          );
        }

        if (entropySample && entropyLength < entropySample.length) {
          const copied = Math.min(chunk.length, entropySample.length - entropyLength);
          chunk.copy(entropySample, entropyLength, 0, copied);
          entropyLength += copied;
        }
        if (staticHeadLength < staticHead.length) {
          const copied = Math.min(chunk.length, staticHead.length - staticHeadLength);
          chunk.copy(staticHead, staticHeadLength, 0, copied);
          staticHeadLength += copied;
        }
        if (retainStaticTail) staticTail = retainTail(staticTail, chunk, STATIC_TAIL_BYTES);

        const window = tail.length ? Buffer.concat([tail, chunk]) : chunk;
        for (let index = 0; index < this.patternRules.length; index++) {
          if (!matchedPatterns.has(index) && patternMatches(window, this.patternRules[index])) matchedPatterns.add(index);
        }
        if (script || peLike) {
          const latin = window.toString('latin1');
          if (script) {
            for (let index = 0; index < SCRIPT_RULES.length; index++) {
              if (!matchedScripts.has(index) && SCRIPT_RULES[index][0].test(latin)) matchedScripts.add(index);
            }
          }
          if (peLike) {
            const folded = latin.toLowerCase();
            for (const api of INJECTION_APIS) if (folded.includes(api)) matchedInjectionApis.add(api);
          }
        }

        const retained = Math.min(overlapBytes, window.length);
        tail = retained ? Buffer.from(window.subarray(window.length - retained)) : Buffer.alloc(0);
        position += bytesRead;
      }

      signal?.throwIfAborted();
      const finalStat = await handle.stat();
      if (identityChanged(openedStat, finalStat) || metadataChanged(openedStat, finalStat)) {
        throw new Error('File changed during scanning');
      }

      result.sha256 = hash.digest('hex');
      for (const index of matchedPatterns) {
        const rule = this.patternRules[index];
        addFinding(result, rule.id, rule.name, rule.score);
      }
      applyFilenameHeuristics(result, file);
      for (const index of matchedScripts) {
        const [, score, description] = SCRIPT_RULES[index];
        addFinding(result, 'heuristic.script', description, score);
      }
      if (matchedInjectionApis.size === INJECTION_APIS.length) {
        addFinding(result, 'heuristic.pe-api-combination', 'Multiple process-injection APIs are imported or referenced', 28);
      }
      const sample = entropySample?.subarray(0, entropyLength) ?? Buffer.alloc(0);
      if (sample.length > 4096 && entropy(sample) > 7.65) {
        addFinding(result, 'heuristic.entropy', 'Unusually high entropy; file may be packed or encrypted', 18);
      }
      const staticAnalysis = analyzeStaticContent({
        file,
        head: staticHead?.subarray(0, staticHeadLength) ?? Buffer.alloc(0),
        tail: staticTail
      });
      result.staticAnalysis = staticAnalysis.metadata;
      for (const finding of staticAnalysis.findings) addFinding(result, finding.id, finding.description, finding.score);
      applyPuaClassification(result, this.definitions);
      if (peLike && this.trustVerifier && heuristicScore(result) >= 25) {
        await applyAuthenticodeTrust(result, file, this.trustVerifier, this.trustedPublisherOrganizations, this.trustedApplicationPolicies);
      }
      const finalized = finalizeResult(result, started, this.definitions, this.threshold);
      this.writeCache(cacheKey, finalized);
      return finalized;
    } finally {
      await handle.close();
    }
  }

  async *walk(root, {
    signal,
    onDiscovered = () => {},
    onTraversalError = () => {},
    onTraversalSkip = () => {},
    excludePaths = this.excludePaths,
    applyNameExclusions = true,
    maxDepth = Number.POSITIVE_INFINITY
  } = {}) {
    const resolvedRoot = path.resolve(root);
    const effectiveExcludePaths = excludePaths.map(normalizePathKey);
    const depthLimit = Number.isFinite(maxDepth) ? Math.max(0, Math.trunc(maxDepth)) : Number.POSITIVE_INFINITY;
    if (this.isExcludedPath(resolvedRoot, effectiveExcludePaths)) return;

    let rootStat;
    try { rootStat = await fs.lstat(resolvedRoot); }
    catch (error) { onTraversalError({ path: resolvedRoot, error: error.message }); return; }
    if (rootStat.isSymbolicLink()) {
      onTraversalSkip({ path: resolvedRoot, reason: 'link' });
      return;
    }
    if (rootStat.isFile()) {
      let canonicalFile;
      try { canonicalFile = await fs.realpath(resolvedRoot); }
      catch (error) { onTraversalError({ path: resolvedRoot, error: error.message }); return; }
      if (this.isExcludedPath(canonicalFile, effectiveExcludePaths)) return;
      onDiscovered({ path: resolvedRoot, size: rootStat.size, identity: snapshotIdentity(rootStat) });
      yield resolvedRoot;
      return;
    }
    if (!rootStat.isDirectory()) return;

    let canonicalRoot;
    try { canonicalRoot = await fs.realpath(resolvedRoot); }
    catch (error) { onTraversalError({ path: resolvedRoot, error: error.message }); return; }
    if (this.isExcludedPath(canonicalRoot, effectiveExcludePaths)) return;

    // Only ancestors are retained. This prevents cycles without growing a set
    // proportional to every directory on a full-drive scan.
    const activeDirectories = new Set([normalizePathKey(canonicalRoot)]);
    const stack = [];
    try {
      try {
        stack.push({
          directory: resolvedRoot,
          canonical: canonicalRoot,
          depth: 0,
          handle: await fs.opendir(resolvedRoot)
        });
      }
      catch (error) { onTraversalError({ path: resolvedRoot, error: error.message }); return; }

      while (stack.length) {
        signal?.throwIfAborted();
        const frame = stack.at(-1);
        let entry;
        try { entry = await frame.handle.read(); }
        catch (error) {
          onTraversalError({ path: frame.directory, error: error.message });
          await closeDirectory(frame.handle);
          stack.pop();
          activeDirectories.delete(normalizePathKey(frame.canonical));
          continue;
        }
        if (!entry) {
          await closeDirectory(frame.handle);
          stack.pop();
          activeDirectories.delete(normalizePathKey(frame.canonical));
          continue;
        }

        const candidate = path.join(frame.directory, entry.name);
        if (this.isTransientPath(candidate)) {
          onTraversalSkip({ path: candidate, reason: 'internal-transient' });
          continue;
        }
        if (this.isExcludedPath(candidate, effectiveExcludePaths)) continue;
        let stat;
        try { stat = await fs.lstat(candidate); }
        catch (error) { onTraversalError({ path: candidate, error: error.message }); continue; }
        if (stat.isSymbolicLink()) {
          onTraversalSkip({ path: candidate, reason: 'link' });
          continue;
        }

        if (stat.isFile()) {
          let canonicalFile;
          try { canonicalFile = await fs.realpath(candidate); }
          catch (error) { onTraversalError({ path: candidate, error: error.message }); continue; }
          if (!isPathWithin(canonicalRoot, canonicalFile)) {
            onTraversalSkip({ path: candidate, reason: 'outside-root' });
            continue;
          }
          if (this.isExcludedPath(canonicalFile, effectiveExcludePaths)) continue;
          onDiscovered({ path: candidate, size: stat.size, identity: snapshotIdentity(stat) });
          yield candidate;
          continue;
        }

        if (!stat.isDirectory() || frame.depth >= depthLimit) continue;
        if (applyNameExclusions && this.exclude.has(entry.name.toLowerCase())) continue;
        let canonicalDirectory;
        try { canonicalDirectory = await fs.realpath(candidate); }
        catch (error) { onTraversalError({ path: candidate, error: error.message }); continue; }
        if (!isPathWithin(canonicalRoot, canonicalDirectory)) {
          onTraversalSkip({ path: candidate, reason: 'outside-root' });
          continue;
        }
        if (this.isExcludedPath(canonicalDirectory, effectiveExcludePaths)) continue;
        const key = normalizePathKey(canonicalDirectory);
        if (activeDirectories.has(key)) {
          onTraversalSkip({ path: candidate, reason: 'duplicate' });
          continue;
        }

        try {
          const handle = await fs.opendir(candidate);
          activeDirectories.add(key);
          stack.push({ directory: candidate, canonical: canonicalDirectory, depth: frame.depth + 1, handle });
        } catch (error) {
          onTraversalError({ path: candidate, error: error.message });
        }
      }
    } finally {
      await Promise.allSettled(stack.map(frame => closeDirectory(frame.handle)));
    }
  }

  async scanPath(root, {
    concurrency = 4,
    onResult = () => {},
    onProgress = () => {},
    onTraversalError = () => {},
    signal
  } = {}) {
    const files = [];
    let bytesDiscovered = 0;
    for await (const file of this.walk(root, {
      signal,
      onTraversalError,
      excludePaths: [],
      onDiscovered: ({ size }) => { bytesDiscovered += size; }
    })) {
      files.push(file);
      onProgress({
        phase: 'discovering', filesDiscovered: files.length, bytesDiscovered,
        completed: 0, total: null, bytesCompleted: 0, currentPath: file
      });
    }
    const results = new Array(files.length);
    let cursor = 0;
    let completed = 0;
    let bytesCompleted = 0;
    onProgress({
      phase: 'scanning', filesDiscovered: files.length, bytesDiscovered,
      completed: 0, total: files.length, bytesCompleted: 0, currentPath: null
    });
    const worker = async () => {
      while (cursor < files.length) {
        signal?.throwIfAborted();
        const index = cursor++;
        try { results[index] = await this.scanFile(files[index], { signal }); }
        catch (error) {
          if (error.name === 'AbortError') throw error;
          results[index] = { path: files[index], verdict: 'error', score: 0, findings: [], error: error.message };
        }
        onResult(results[index]);
        completed++;
        bytesCompleted += results[index].size ?? 0;
        onProgress({
          phase: 'scanning', filesDiscovered: files.length, bytesDiscovered,
          completed, total: files.length, bytesCompleted, currentPath: files[index]
        });
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, 32)) }, worker));
    return results;
  }

  async scanPathStreaming(root, {
    concurrency = 2,
    exhaustive = false,
    maxDepth = Number.POSITIVE_INFINITY,
    applyNameExclusions = true,
    excludePaths = this.excludePaths,
    onResult = () => {},
    onProgress = () => {},
    onTraversalError = () => {},
    onTraversalSkip = () => {},
    signal
  } = {}) {
    const limit = Math.max(1, Math.min(concurrency, 2));
    const pending = new Set();
    let filesDiscovered = 0;
    let bytesDiscovered = 0;
    let completed = 0;
    let bytesCompleted = 0;
    let traversalSkipped = 0;
    let failure = null;
    let latestDiscovery = null;

    const schedule = (file, expectedIdentity) => {
      let operation;
      operation = (async () => {
        let result;
        try {
          result = exhaustive
            ? await this.scanFileExhaustive(file, { signal, expectedIdentity })
            : await this.scanFile(file, { signal, expectedIdentity });
        } catch (error) {
          if (error.name === 'AbortError') throw error;
          result = { path: file, verdict: 'error', score: 0, findings: [], error: error.message };
        }
        signal?.throwIfAborted();
        await onResult(result);
        signal?.throwIfAborted();
        completed++;
        bytesCompleted += result.size ?? 0;
        onProgress({
          phase: 'scanning', filesDiscovered, bytesDiscovered,
          completed, total: null, bytesCompleted, traversalSkipped, currentPath: file
        });
      })().catch(error => { failure ??= error; }).finally(() => pending.delete(operation));
      pending.add(operation);
    };

    onProgress({
      phase: 'scanning', filesDiscovered, bytesDiscovered,
      completed, total: null, bytesCompleted, traversalSkipped, currentPath: null
    });
    try {
      for await (const file of this.walk(root, {
        signal,
        maxDepth,
        applyNameExclusions,
        excludePaths,
        onTraversalError,
        onTraversalSkip: detail => {
          traversalSkipped++;
          onTraversalSkip(detail);
        },
        onDiscovered: discovery => {
          const { size } = discovery;
          latestDiscovery = discovery;
          filesDiscovered++;
          bytesDiscovered += size;
        }
      })) {
        signal?.throwIfAborted();
        const expectedIdentity = latestDiscovery?.path === file ? latestDiscovery.identity : undefined;
        latestDiscovery = null;
        schedule(file, expectedIdentity);
        if (pending.size >= limit) await Promise.race(pending);
        if (failure) break;
      }
    } catch (error) {
      failure ??= error;
    } finally {
      // Scheduled work catches into `failure`; draining guarantees no result or
      // progress callback can fire after this method settles.
      await Promise.all(pending);
    }
    if (failure) throw failure;
    signal?.throwIfAborted();
    return { filesDiscovered, bytesDiscovered, completed, bytesCompleted, traversalSkipped };
  }

  isExcludedPath(candidate, excludePaths = this.excludePaths) {
    const key = normalizePathKey(candidate);
    return excludePaths.some(excluded => key === excluded || key.startsWith(`${excluded}${path.sep}`));
  }

  createCacheKey(file, stat, maximumBytes) {
    const namespace = this.computeCacheNamespace();
    if (namespace !== this.cacheNamespace) {
      this.scanCache.clear();
      this.cacheNamespace = namespace;
    }
    const resolved = normalizePathKey(path.resolve(file));
    const limit = stat.size <= maximumBytes ? 'full' : Number.isFinite(maximumBytes) ? maximumBytes : 'all';
    return [namespace, resolved, stat.dev, stat.ino, stat.size, stat.mtimeMs, stat.ctimeMs, limit].join('|');
  }

  computeCacheNamespace() {
    return JSON.stringify({
      definitionsVersion: String(this.definitions?.version ?? ''),
      threshold: this.threshold,
      trustedPublishers: [...this.trustedPublisherOrganizations].sort(),
      trustedApplications: this.trustedApplicationPolicies
    });
  }

  readCache(key, now = Date.now()) {
    if (!this.cacheMaxEntries || !this.cacheTtlMs) return null;
    const entry = this.scanCache.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= now) {
      this.scanCache.delete(key);
      return null;
    }
    this.scanCache.delete(key);
    this.scanCache.set(key, entry);
    return structuredClone(entry.result);
  }

  writeCache(key, result, now = Date.now()) {
    if (!this.cacheMaxEntries || !this.cacheTtlMs || result.verdict === 'skipped' || result.verdict === 'error') return;
    this.scanCache.delete(key);
    this.scanCache.set(key, { expiresAt: now + this.cacheTtlMs, result: structuredClone(result) });
    while (this.scanCache.size > this.cacheMaxEntries) this.scanCache.delete(this.scanCache.keys().next().value);
  }

  getPerformanceMetrics() {
    return {
      ...this.performance,
      cacheEntries: this.scanCache.size,
      cacheMaxEntries: this.cacheMaxEntries,
      cacheTtlMs: this.cacheTtlMs
    };
  }
}

function hasSupportedStaticMagic(buffer) {
  return buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a
    || isZipMagic(buffer)
    || buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from('d0cf11e0a1b11ae1', 'hex'))
    || buffer.length >= 6 && buffer.subarray(0, 6).equals(Buffer.from('377abcaf271c', 'hex'))
    || buffer.length >= 7 && buffer.subarray(0, 7).equals(Buffer.from('526172211a0700', 'hex'));
}

function isZipMagic(buffer) {
  return buffer.length >= 4 && [0x04034b50, 0x06054b50, 0x08074b50].includes(buffer.readUInt32LE(0));
}

function clampInteger(value, minimum, maximum, fallback) {
  return Number.isSafeInteger(value) ? Math.max(minimum, Math.min(maximum, value)) : fallback;
}

function createResult(file, size) {
  return {
    path: path.resolve(file), size, sha256: null, score: 0,
    verdict: 'clean', findings: [], durationMs: 0
  };
}

function addFinding(result, id, description, score) {
  result.findings.push({ id, description, score });
}

function applyFilenameHeuristics(result, file) {
  const lower = path.basename(file).toLowerCase();
  const ext = path.extname(lower);
  const stemExt = path.extname(lower.slice(0, -ext.length));
  if (EXECUTABLE.has(ext) && LURE.has(stemExt)) {
    addFinding(result, 'heuristic.double-extension', 'Executable disguised with a document/image extension', 45);
  }
}

function finalizeResult(result, started, definitions, threshold) {
  const known = definitions.sha256?.[result.sha256];
  if (known) addFinding(result, 'signature.sha256', known, 100);
  result.score = Math.max(0, Math.min(100, result.findings.reduce((sum, finding) => sum + finding.score, 0)));
  result.verdict = result.score >= threshold ? 'malicious' : result.score >= 25 ? 'suspicious' : 'clean';
  if (result.classification === 'pua' && result.verdict === 'malicious' && !result.findings.some(finding => finding.id === 'signature.sha256')) result.verdict = 'suspicious';
  result.durationMs = elapsed(started);
  return result;
}

function applyPuaClassification(result, definitions) {
  const matches = Array.isArray(definitions.puaSha256?.[result.sha256])
    ? definitions.puaSha256[result.sha256]
    : definitions.puaSha256?.[result.sha256] ? [definitions.puaSha256[result.sha256]] : [];
  if (!matches.length) return;
  result.classification = 'pua';
  for (const description of matches.slice(0, 8)) addFinding(result, 'pua.sha256', String(description).slice(0, 500), 35);
}

function heuristicScore(result) {
  return result.findings.reduce((sum, finding) => sum + Math.max(0, finding.score), 0);
}

async function applyAuthenticodeTrust(result, file, verifier, trustedOrganizations, trustedApplications) {
  try {
    const trust = await verifier(file, result.sha256);
    if (!trust || typeof trust !== 'object') return;
    result.trust = {
      status: String(trust.status ?? 'unknown').slice(0, 80),
      subject: String(trust.subject ?? '').slice(0, 500),
      organization: String(trust.organization ?? '').slice(0, 200),
      isOsBinary: trust.isOsBinary === true,
      statusMessage: String(trust.statusMessage ?? '').slice(0, 300),
      signatureType: String(trust.signatureType ?? '').slice(0, 80),
      thumbprint: String(trust.thumbprint ?? '').slice(0, 100),
      notBefore: String(trust.notBefore ?? '').slice(0, 80),
      notAfter: String(trust.notAfter ?? '').slice(0, 80),
      chainValid: trust.chainValid === true,
      chainStatus: Array.isArray(trust.chainStatus) ? trust.chainStatus.map(value => String(value).slice(0, 80)).slice(0, 16) : [],
      timestamped: trust.timestamped === true,
      timestampSubject: String(trust.timestampSubject ?? '').slice(0, 500),
      companyName: String(trust.companyName ?? '').slice(0, 200),
      productName: String(trust.productName ?? '').slice(0, 200),
      fileVersion: String(trust.fileVersion ?? '').slice(0, 100),
      zoneId: Number.isSafeInteger(trust.zoneId) ? trust.zoneId : null,
      origin: classifyOrigin(file)
    };
    const organization = normalizePublisher(result.trust.organization);
    const lowConfidenceOnly = result.findings.every(finding => TRUST_DISCOUNTABLE.has(finding.id));
    const trustedApplication = trustedApplications.some(policy =>
      policy.publisher === organization && policy.roots.some(root => isPathWithin(root, file))
    );
    const trustedSigner = result.trust.isOsBinary || trustedOrganizations.has(organization) || trustedApplication;
    result.trust.applicationVerified = trustedApplication;
    result.trust.trustedPublisher = result.trust.status === 'valid' && trustedSigner;
    if (result.trust.status === 'valid' && trustedSigner && lowConfidenceOnly) {
      const discount = heuristicScore(result);
      const publisher = result.trust.organization || (result.trust.isOsBinary ? 'Microsoft Windows OS binary' : 'trusted publisher');
      if (discount > 0) addFinding(result, 'trust.authenticode', `Valid signature from trusted publisher: ${publisher}`, -discount);
    }
  } catch {
    // Signature verification is enrichment. Failure must not make a file clean
    // or turn an otherwise successful content scan into an operational error.
  }
}

function classifyOrigin(file) {
  const policies = [
    ['windows', process.env.SystemRoot],
    ['program-files', process.env.ProgramFiles],
    ['program-files-x86', process.env['ProgramFiles(x86)']],
    ['installed-user-application', process.env.LOCALAPPDATA]
  ];
  for (const [label, root] of policies) if (root && isPathWithin(root, file)) return label;
  return 'other';
}

function normalizePublisher(value) {
  return String(value ?? '').trim().replace(/\s+/g, ' ').toLowerCase();
}

function normalizeApplicationPolicies(value) {
  if (!Array.isArray(value)) return [];
  return value.map(policy => ({
    publisher: normalizePublisher(policy?.publisher),
    roots: Array.isArray(policy?.roots) ? policy.roots.map(expandEnvironmentPath).filter(Boolean) : []
  })).filter(policy => policy.publisher && policy.roots.length);
}

function expandEnvironmentPath(value) {
  if (typeof value !== 'string' || !value) return null;
  const expanded = value.replace(/%([^%]+)%/g, (_match, name) => {
    const key = Object.keys(process.env).find(candidate => candidate.toLowerCase() === name.toLowerCase());
    return key ? process.env[key] : '';
  });
  return path.isAbsolute(expanded) ? path.resolve(expanded) : null;
}

function elapsed(started) {
  return Math.round((performance.now() - started) * 10) / 10;
}

function normalizeChunkSize(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || number > 4 * 1024 * 1024) {
    throw new TypeError('Invalid streaming chunk size');
  }
  return number;
}

function identityChanged(before, after) {
  if (before.dev && after.dev && before.dev !== after.dev) return true;
  return Boolean(before.ino && after.ino && before.ino !== after.ino);
}

function snapshotIdentity(stat) {
  return { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs };
}

function snapshotChanged(expected, actual) {
  return identityChanged(expected, actual) || metadataChanged(expected, actual);
}

function metadataChanged(before, after) {
  return before.size !== after.size || before.mtimeMs !== after.mtimeMs;
}

async function closeDirectory(handle) {
  try { await handle.close(); }
  catch (error) { if (error.code !== 'ERR_DIR_CLOSED') throw error; }
}

function isPathWithin(root, candidate) {
  const rootKey = normalizePathKey(root);
  const candidateKey = normalizePathKey(candidate);
  if (rootKey === candidateKey) return true;
  const relative = path.relative(rootKey, candidateKey);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function normalizePathKey(value) {
  const resolved = path.resolve(value);
  const root = path.parse(resolved).root;
  const withoutTrailing = resolved === root ? resolved : resolved.replace(/[\\/]+$/, '');
  return process.platform === 'win32' ? withoutTrailing.toLowerCase() : withoutTrailing;
}

function retainTail(previous, chunk, maximum) {
  if (chunk.length >= maximum) return Buffer.from(chunk.subarray(chunk.length - maximum));
  const combined = previous.length ? Buffer.concat([previous, chunk]) : Buffer.from(chunk);
  return combined.length <= maximum ? combined : Buffer.from(combined.subarray(combined.length - maximum));
}

function compileDefinitionPattern(rule) {
  if (typeof rule.hex === 'string') {
    const tokens = rule.hex.trim().split(/\s+/);
    return {
      bytes: Buffer.from(tokens.map(token => token === '??' ? 0 : Number.parseInt(token, 16))),
      mask: Buffer.from(tokens.map(token => token === '??' ? 0 : 0xff))
    };
  }
  return {
    bytes: rule.literalBase64
      ? Buffer.from(rule.literalBase64, 'base64')
      : Buffer.from(String(rule.literal ?? ''), 'latin1'),
    mask: null
  };
}

function patternMatches(buffer, rule) {
  if (!rule.mask) return buffer.includes(rule.bytes);
  outer: for (let offset = 0; offset <= buffer.length - rule.bytes.length; offset++) {
    for (let index = 0; index < rule.bytes.length; index++) {
      if (rule.mask[index] && buffer[offset + index] !== rule.bytes[index]) continue outer;
    }
    return true;
  }
  return false;
}
