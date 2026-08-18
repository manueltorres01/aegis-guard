import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const EXECUTABLE = new Set(['.exe', '.dll', '.scr', '.com', '.msi', '.jar', '.ps1', '.vbs', '.js', '.jse', '.bat', '.cmd', '.hta']);
const LURE = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.jpeg', '.png', '.txt']);
const SCRIPT_RULES = [
  [/powershell(?:\.exe)?\s+[^\r\n]{0,160}-(?:enc|encodedcommand)\b/i, 35, 'Encoded PowerShell command'],
  [/(?:frombase64string|invoke-expression|\biex\b)/i, 18, 'Script obfuscation/execution primitive'],
  [/(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)/i, 55, 'Shadow-copy deletion'],
  [/(?:createremotethread|virtualalloc(?:ex)?|writeprocessmemory)/i, 28, 'Process-injection API combination'],
  [/(?:document_open|autoopen|workbook_open)/i, 20, 'Office auto-execution macro'],
  [/(?:rundll32|regsvr32|mshta)\.exe\s+(?:https?:|javascript:)/i, 40, 'Living-off-the-land remote execution']
];

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
  constructor({ definitions, threshold = 60, maxFileSizeMb = 128, exclude = [] }) {
    this.definitions = definitions;
    this.threshold = threshold;
    this.maxBytes = maxFileSizeMb * 1024 * 1024;
    this.exclude = new Set(exclude.map(x => x.toLowerCase()));
  }

  async scanFile(file) {
    const started = performance.now();
    const stat = await fs.stat(file);
    const result = { path: path.resolve(file), size: stat.size, sha256: null, score: 0, verdict: 'clean', findings: [], durationMs: 0 };
    if (!stat.isFile()) throw new Error('Not a regular file');
    if (stat.size > this.maxBytes) {
      result.verdict = 'skipped';
      result.findings.push({ id: 'limit.size', description: 'File exceeds configured scan size', score: 0 });
      return result;
    }
    const data = await fs.readFile(file);
    result.sha256 = crypto.createHash('sha256').update(data).digest('hex');
    const add = (id, description, score) => result.findings.push({ id, description, score });
    const known = this.definitions.sha256?.[result.sha256];
    if (known) add('signature.sha256', known, 100);
    const latin = data.toString('latin1');
    for (const rule of this.definitions.patterns ?? []) {
      const literal = rule.literalBase64
        ? Buffer.from(rule.literalBase64, 'base64').toString('latin1')
        : rule.literal;
      if (literal && latin.includes(literal)) add(rule.id, rule.name, rule.score);
    }

    const lower = path.basename(file).toLowerCase();
    const ext = path.extname(lower);
    const stemExt = path.extname(lower.slice(0, -ext.length));
    if (EXECUTABLE.has(ext) && LURE.has(stemExt)) add('heuristic.double-extension', 'Executable disguised with a document/image extension', 45);
    if (EXECUTABLE.has(ext)) {
      for (const [regex, score, description] of SCRIPT_RULES) if (regex.test(latin)) add('heuristic.script', description, score);
      const sample = data.subarray(0, Math.min(data.length, 1024 * 1024));
      if (sample.length > 4096 && entropy(sample) > 7.65) add('heuristic.entropy', 'Unusually high entropy; file may be packed or encrypted', 18);
    }
    result.score = Math.min(100, result.findings.reduce((sum, x) => sum + x.score, 0));
    result.verdict = result.score >= this.threshold ? 'malicious' : result.score >= 25 ? 'suspicious' : 'clean';
    result.durationMs = Math.round((performance.now() - started) * 10) / 10;
    return result;
  }

  async *walk(root) {
    const pending = [path.resolve(root)];
    while (pending.length) {
      const current = pending.pop();
      let stat;
      try { stat = await fs.lstat(current); } catch { continue; }
      if (stat.isSymbolicLink()) continue;
      if (stat.isFile()) { yield current; continue; }
      if (!stat.isDirectory()) continue;
      let entries;
      try { entries = await fs.readdir(current, { withFileTypes: true }); } catch { continue; }
      for (const entry of entries) {
        if (entry.isDirectory() && this.exclude.has(entry.name.toLowerCase())) continue;
        pending.push(path.join(current, entry.name));
      }
    }
  }

  async scanPath(root, { concurrency = 4, onResult = () => {} } = {}) {
    const files = [];
    for await (const file of this.walk(root)) files.push(file);
    const results = new Array(files.length);
    let cursor = 0;
    const worker = async () => {
      while (cursor < files.length) {
        const index = cursor++;
        try { results[index] = await this.scanFile(files[index]); }
        catch (error) { results[index] = { path: files[index], verdict: 'error', score: 0, findings: [], error: error.message }; }
        onResult(results[index]);
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, 32)) }, worker));
    return results;
  }
}
