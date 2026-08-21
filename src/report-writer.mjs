import fs from 'node:fs/promises';
import path from 'node:path';

const CSV_COLUMNS = ['path', 'verdict', 'classification', 'score', 'size', 'sha256', 'reason', 'error', 'action', 'signatureStatus', 'signatureType', 'publisher', 'companyName', 'productName', 'fileVersion', 'origin', 'zoneId', 'verifiedApplication', 'chainValid', 'chainStatus', 'timestamped', 'certificateThumbprint', 'certificateSubject', 'trustReason', 'staticAnalysis'];

export class ScanReportWriter {
  constructor({ directory, scanId, mode, target, startedAt }) {
    this.directory = path.resolve(directory);
    this.scanId = scanId;
    this.mode = mode;
    this.target = target ?? null;
    this.startedAt = new Date(startedAt).toISOString();
    this.queue = Promise.resolve();
    this.failed = null;
    this.count = 0;
  }

  async init() {
    await fs.mkdir(this.directory, { recursive: true });
    const base = `scan-${this.startedAt.replace(/[:.]/g, '-')}-${this.scanId}`;
    this.jsonPath = path.join(this.directory, `${base}.json`);
    this.csvPath = path.join(this.directory, `${base}.csv`);
    this.jsonTemporary = `${this.jsonPath}.partial`;
    this.csvTemporary = `${this.csvPath}.partial`;
    const header = JSON.stringify({ format: 1, scanId: this.scanId, mode: this.mode, target: this.target, startedAt: this.startedAt });
    this.jsonHandle = await fs.open(this.jsonTemporary, 'wx');
    try { this.csvHandle = await fs.open(this.csvTemporary, 'wx'); }
    catch (error) { await this.jsonHandle.close(); throw error; }
    await Promise.all([
      this.jsonHandle.writeFile(`${header.slice(0, -1)},"results":[\n`),
      this.csvHandle.writeFile(`${CSV_COLUMNS.map(csvCell).join(',')}\r\n`)
    ]);
    return this;
  }

  async append(result) {
    if (this.failed) return false;
    this.queue = this.queue.then(async () => {
      const normalized = normalizeResult(result);
      await Promise.all([
        this.jsonHandle.writeFile(`${this.count ? ',\n' : ''}${JSON.stringify(normalized)}`),
        this.csvHandle.writeFile(`${CSV_COLUMNS.map(key => csvCell(normalized[key])).join(',')}\r\n`)
      ]);
      this.count++;
    }).catch(error => { this.failed = error; });
    await this.queue;
    return !this.failed;
  }

  async finalize({ completedAt, cancelled = false, summary, resultsTruncated = 0 }) {
    await this.queue;
    if (this.failed) { await this.abort(); return null; }
    try {
      await this.jsonHandle.writeFile(`\n],"completedAt":${JSON.stringify(completedAt)},"cancelled":${Boolean(cancelled)},"summary":${JSON.stringify(summary)},"uiDetailsTruncated":${Math.max(0, Number(resultsTruncated) || 0)}}\n`);
      await Promise.all([this.jsonHandle.close(), this.csvHandle.close()]);
      this.jsonHandle = null;
      this.csvHandle = null;
      await Promise.all([fs.rename(this.jsonTemporary, this.jsonPath), fs.rename(this.csvTemporary, this.csvPath)]);
      return { scanId: this.scanId, completedAt, count: this.count, jsonFile: path.basename(this.jsonPath), csvFile: path.basename(this.csvPath) };
    } catch (error) {
      this.failed = error;
      await this.abort();
      return null;
    }
  }

  async abort() {
    await this.queue.catch(() => {});
    await Promise.allSettled([this.jsonHandle?.close(), this.csvHandle?.close()]);
    this.jsonHandle = null;
    this.csvHandle = null;
    await Promise.allSettled([
      this.jsonTemporary && fs.rm(this.jsonTemporary, { force: true }),
      this.csvTemporary && fs.rm(this.csvTemporary, { force: true })
    ]);
  }
}

function normalizeResult(result = {}) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const trustFinding = findings.find(finding => finding?.id === 'trust.authenticode');
  return {
    path: String(result.path ?? ''), verdict: String(result.verdict ?? 'error'),
    classification: String(result.classification ?? 'malware'),
    score: Number.isFinite(result.score) ? result.score : 0,
    size: Number.isFinite(result.size) ? result.size : null,
    sha256: typeof result.sha256 === 'string' ? result.sha256 : null,
    reason: String(findings[0]?.description ?? findings[0]?.id ?? ''),
    findings: findings.map(finding => ({ id: String(finding?.id ?? ''), description: String(finding?.description ?? ''), score: Number.isFinite(finding?.score) ? finding.score : 0 })),
    error: result.error ? String(result.error) : '', action: String(result.action ?? ''),
    signatureStatus: String(result.trust?.status ?? ''), publisher: String(result.trust?.organization ?? ''),
    signatureType: String(result.trust?.signatureType ?? ''),
    companyName: String(result.trust?.companyName ?? ''), productName: String(result.trust?.productName ?? ''),
    fileVersion: String(result.trust?.fileVersion ?? ''), origin: String(result.trust?.origin ?? ''),
    zoneId: Number.isSafeInteger(result.trust?.zoneId) ? result.trust.zoneId : null,
    verifiedApplication: result.trust?.applicationVerified === true,
    chainValid: result.trust?.chainValid === true,
    chainStatus: Array.isArray(result.trust?.chainStatus) ? result.trust.chainStatus : [],
    timestamped: result.trust?.timestamped === true,
    certificateThumbprint: String(result.trust?.thumbprint ?? ''),
    certificateSubject: String(result.trust?.subject ?? ''), trustReason: String(trustFinding?.description ?? ''),
    staticAnalysis: result.staticAnalysis && typeof result.staticAnalysis === 'object' ? result.staticAnalysis : {}
  };
}

function csvCell(value) {
  let text = value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

