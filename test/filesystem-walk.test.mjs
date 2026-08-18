import test from 'node:test';
import assert from 'node:assert/strict';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ScanEngine } from '../src/engine.mjs';

const execFileAsync = promisify(execFile);
const definitions = { sha256: {}, patterns: [] };

async function temporaryRoot(t, prefix) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

function createEngine() {
  return new ScanEngine({ definitions, threshold: 60, maxFileSizeMb: 1 });
}

test('walk scans dotfiles, dot-directories and deeply nested descendants', async t => {
  const root = await temporaryRoot(t, 'aegis-walk-hidden-');
  const dotfile = path.join(root, '.hidden-fixture.txt');
  const dotDirectoryFile = path.join(root, '.hidden-directory', 'inside.txt');
  let deepest = root;
  for (let depth = 0; depth < 32; depth++) deepest = path.join(deepest, `level-${depth}`);
  const deepFile = path.join(deepest, 'deep.txt');
  await Promise.all([
    fs.mkdir(path.dirname(dotDirectoryFile), { recursive: true }),
    fs.mkdir(path.dirname(deepFile), { recursive: true })
  ]);
  await Promise.all([
    fs.writeFile(dotfile, 'portable dotfile fixture'),
    fs.writeFile(dotDirectoryFile, 'portable dot-directory fixture'),
    fs.writeFile(deepFile, 'deep descendant fixture')
  ]);

  const results = await createEngine().scanPath(root);
  const paths = new Set(results.map(result => result.path));
  assert.equal(results.length, 3);
  assert.equal(paths.has(path.resolve(dotfile)), true);
  assert.equal(paths.has(path.resolve(dotDirectoryFile)), true);
  assert.equal(paths.has(path.resolve(deepFile)), true);
});

test('walk scans a file carrying the Windows hidden attribute', {
  skip: process.platform !== 'win32' && 'Windows-only filesystem attribute'
}, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-walk-attribute-'));
  const hiddenFile = path.join(root, 'attribute-hidden.txt');
  await fs.writeFile(hiddenFile, 'Windows hidden-attribute fixture');
  t.after(async () => {
    try { await execFileAsync('attrib.exe', ['-H', hiddenFile], { windowsHide: true }); }
    catch { /* cleanup can continue if the file was already removed */ }
    await fs.rm(root, { recursive: true, force: true });
  });

  await execFileAsync('attrib.exe', ['+H', hiddenFile], { windowsHide: true });
  const { stdout } = await execFileAsync('attrib.exe', [hiddenFile], { encoding: 'utf8', windowsHide: true });
  assert.match(stdout, /\bH\b/);

  const results = await createEngine().scanPath(root);
  assert.equal(results.length, 1);
  assert.equal(results[0].path, path.resolve(hiddenFile));
});

test('walk reports a directory that disappears and continues with the discovered sibling', async t => {
  const root = await temporaryRoot(t, 'aegis-walk-race-directory-');
  const firstDirectory = path.join(root, 'first');
  const secondDirectory = path.join(root, 'second');
  await Promise.all([
    fs.mkdir(firstDirectory),
    fs.mkdir(secondDirectory)
  ]);
  await Promise.all([
    fs.writeFile(path.join(firstDirectory, 'file.txt'), 'first fixture'),
    fs.writeFile(path.join(secondDirectory, 'file.txt'), 'second fixture')
  ]);

  const traversalErrors = [];
  const iterator = createEngine().walk(root, {
    onTraversalError: error => traversalErrors.push(error)
  });
  const first = await iterator.next();
  assert.equal(first.done, false);
  const yieldedDirectory = path.dirname(first.value);
  const disappearingDirectory = yieldedDirectory === firstDirectory ? secondDirectory : firstDirectory;
  await fs.rm(disappearingDirectory, { recursive: true });

  const remaining = [];
  for await (const file of iterator) remaining.push(file);
  assert.deepEqual(remaining, []);
  assert.equal(traversalErrors.length, 1);
  assert.equal(path.resolve(traversalErrors[0].path), path.resolve(disappearingDirectory));
});

test('scanPath returns an error result for a file removed after discovery and scans the survivor', async t => {
  const root = await temporaryRoot(t, 'aegis-walk-race-file-');
  const disappearingFile = path.join(root, 'disappearing.txt');
  const survivingFile = path.join(root, 'surviving.txt');
  await Promise.all([
    fs.writeFile(disappearingFile, 'temporary fixture'),
    fs.writeFile(survivingFile, 'surviving fixture')
  ]);

  let removed = false;
  const results = await createEngine().scanPath(root, {
    onProgress: progress => {
      if (!removed && progress.phase === 'scanning' && progress.completed === 0) {
        fsSync.unlinkSync(disappearingFile);
        removed = true;
      }
    }
  });

  assert.equal(removed, true);
  assert.equal(results.length, 2);
  assert.equal(results.find(result => result.path === path.resolve(disappearingFile))?.verdict, 'error');
  assert.equal(results.find(result => result.path === path.resolve(survivingFile))?.verdict, 'clean');
});

test('exhaustive streaming records a racing deletion and continues scanning', async t => {
  const root = await temporaryRoot(t, 'aegis-walk-stream-race-');
  const disappearingFile = path.join(root, 'disappearing.txt');
  const survivingFile = path.join(root, 'surviving.txt');
  await Promise.all([
    fs.writeFile(disappearingFile, 'temporary streaming fixture'),
    fs.writeFile(survivingFile, 'surviving streaming fixture')
  ]);

  const engine = createEngine();
  const scanFileExhaustive = engine.scanFileExhaustive.bind(engine);
  engine.scanFileExhaustive = async (file, options) => {
    if (path.resolve(file) === path.resolve(disappearingFile)) await fs.unlink(disappearingFile);
    return scanFileExhaustive(file, options);
  };
  const results = [];
  const totals = await engine.scanPathStreaming(root, {
    exhaustive: true,
    onResult: result => results.push(result)
  });

  assert.equal(totals.completed, 2);
  assert.equal(results.length, 2);
  assert.equal(results.find(result => result.path === path.resolve(disappearingFile))?.verdict, 'error');
  assert.equal(results.find(result => result.path === path.resolve(survivingFile))?.verdict, 'clean');
});

test('walk reports an unreadable directory and continues when the host enforces POSIX modes', async t => {
  if (process.platform === 'win32') {
    t.skip('Windows chmod does not create a portable access-denied directory');
    return;
  }
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-walk-permission-'));
  const restricted = path.join(root, 'restricted');
  const readableFile = path.join(root, 'readable.txt');
  await fs.mkdir(restricted);
  await fs.writeFile(path.join(restricted, 'private.txt'), 'restricted fixture');
  await fs.writeFile(readableFile, 'readable fixture');
  await fs.chmod(restricted, 0o000);
  t.after(async () => {
    try { await fs.chmod(restricted, 0o700); }
    catch { /* the directory may already be gone */ }
    await fs.rm(root, { recursive: true, force: true });
  });

  try {
    await fs.readdir(restricted);
    t.skip('Current identity can bypass the directory mode');
    return;
  } catch (error) {
    if (!['EACCES', 'EPERM'].includes(error.code)) throw error;
  }

  const traversalErrors = [];
  const results = await createEngine().scanPath(root, {
    onTraversalError: error => traversalErrors.push(error)
  });
  assert.equal(results.some(result => result.path === path.resolve(readableFile)), true);
  assert.equal(traversalErrors.some(error => error.path === path.resolve(restricted)), true);
});

test('walk does not follow a directory symlink or Windows junction outside the root', async t => {
  const parent = await temporaryRoot(t, 'aegis-walk-link-');
  const scanRoot = path.join(parent, 'selected-root');
  const outsideRoot = path.join(parent, 'outside-root');
  const localFile = path.join(scanRoot, 'local.txt');
  const outsideFile = path.join(outsideRoot, 'outside.txt');
  const link = path.join(scanRoot, 'linked-outside');
  await Promise.all([
    fs.mkdir(scanRoot),
    fs.mkdir(outsideRoot)
  ]);
  await Promise.all([
    fs.writeFile(localFile, 'local fixture'),
    fs.writeFile(outsideFile, 'must not be followed')
  ]);
  try {
    await fs.symlink(outsideRoot, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    if (['EPERM', 'EACCES', 'ENOSYS'].includes(error.code)) {
      t.skip(`Host cannot create a directory link: ${error.code}`);
      return;
    }
    throw error;
  }

  const results = await createEngine().scanPath(scanRoot);
  assert.deepEqual(results.map(result => result.path), [path.resolve(localFile)]);
  assert.equal(results.some(result => result.path === path.resolve(outsideFile)), false);
});

test('walk skips only an exact active Aegis temporary path and still scans lookalike or orphan names', async t => {
  const root = await temporaryRoot(t, 'aegis-walk-transient-');
  const active = path.join(root, '.aegis-76d2809c-2614-45df-908f-587506ab3949.quarantine-tmp');
  const orphan = path.join(root, '.aegis-182452d6-a237-4a12-9552-f29849535227.quarantine-tmp');
  const lookalike = path.join(root, '.aegis-not-a-uuid.quarantine-tmp');
  await Promise.all([
    fs.writeFile(active, 'active internal temporary'),
    fs.writeFile(orphan, 'orphaned temporary must be scanned'),
    fs.writeFile(lookalike, 'lookalike must be scanned')
  ]);

  const results = [];
  const skipped = [];
  const activeKey = process.platform === 'win32' ? path.resolve(active).toLowerCase() : path.resolve(active);
  const engine = new ScanEngine({
    definitions,
    maxFileSizeMb: 1,
    isTransientPath: candidate => {
      const key = process.platform === 'win32' ? path.resolve(candidate).toLowerCase() : path.resolve(candidate);
      return key === activeKey;
    }
  });
  await engine.scanPathStreaming(root, {
    onResult: result => results.push(result),
    onTraversalSkip: detail => skipped.push(detail)
  });

  assert.deepEqual(
    new Set(results.map(result => result.path)),
    new Set([path.resolve(orphan), path.resolve(lookalike)])
  );
  assert.equal(skipped.length, 1);
  assert.equal(skipped[0].reason, 'internal-transient');
  assert.equal(path.resolve(skipped[0].path), path.resolve(active));
});
