import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathExists, resolveInside } from './util.mjs';

export class Quarantine {
  constructor(directory) { this.directory = path.resolve(directory); }

  async init() {
    await fs.mkdir(this.directory, { recursive: true });
    const keyFile = path.join(this.directory, '.key');
    if (!await pathExists(keyFile)) await fs.writeFile(keyFile, crypto.randomBytes(32), { mode: 0o600, flag: 'wx' });
    this.key = await fs.readFile(keyFile);
  }

  async isolate(file, scan) {
    await this.init();
    const source = path.resolve(file);
    const id = crypto.randomUUID();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const clear = await fs.readFile(source);
    const actualHash = crypto.createHash('sha256').update(clear).digest('hex');
    if (!scan.sha256 || actualHash !== scan.sha256) {
      throw new Error('File changed after scanning; refusing to quarantine it');
    }
    const encrypted = Buffer.concat([cipher.update(clear), cipher.final()]);
    const metadata = {
      id, originalPath: source, quarantinedAt: new Date().toISOString(), sha256: scan.sha256,
      verdict: scan.verdict, score: scan.score, findings: scan.findings,
      iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64')
    };
    await fs.writeFile(resolveInside(this.directory, `${id}.bin`), encrypted, { flag: 'wx' });
    await fs.writeFile(resolveInside(this.directory, `${id}.json`), JSON.stringify(metadata, null, 2), { flag: 'wx' });
    await fs.unlink(source);
    return metadata;
  }

  async list() {
    await this.init();
    const names = (await fs.readdir(this.directory)).filter(x => x.endsWith('.json'));
    return Promise.all(names.map(x => fs.readFile(resolveInside(this.directory, x), 'utf8').then(JSON.parse)));
  }

  async restore(id, destination) {
    await this.init();
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('Invalid quarantine identifier');
    const metaFile = resolveInside(this.directory, `${id}.json`);
    const binFile = resolveInside(this.directory, `${id}.bin`);
    const metadata = JSON.parse(await fs.readFile(metaFile, 'utf8'));
    const target = path.resolve(destination ?? metadata.originalPath);
    if (await pathExists(target)) throw new Error(`Refusing to overwrite existing file: ${target}`);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(metadata.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(metadata.tag, 'base64'));
    const clear = Buffer.concat([decipher.update(await fs.readFile(binFile)), decipher.final()]);
    const actual = crypto.createHash('sha256').update(clear).digest('hex');
    if (actual !== metadata.sha256) throw new Error('Quarantine integrity check failed');
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, clear, { flag: 'wx' });
    await fs.unlink(binFile);
    await fs.unlink(metaFile);
    return target;
  }
}
