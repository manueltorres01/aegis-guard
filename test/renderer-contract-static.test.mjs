import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const rendererFile = fileURLToPath(new URL('../desktop/renderer/app.js', import.meta.url));
const rendererHtmlFile = fileURLToPath(new URL('../desktop/renderer/index.html', import.meta.url));
const desktopMainFile = fileURLToPath(new URL('../desktop/main.mjs', import.meta.url));

test('renderer handles STATE_NOT_PERSISTED scan warnings visibly', async () => {
  const source = await fs.readFile(rendererFile, 'utf8');
  const start = source.indexOf("if (type === 'scan-warning')");
  assert.notEqual(start, -1, 'scan-warning handler is missing');
  const nextHandler = source.indexOf("\n  if (type === '", start + 1);
  const block = source.slice(start, nextHandler === -1 ? source.length : nextHandler);
  assert.match(block, /STATE_NOT_PERSISTED/);
  assert.match(block, /showToast\s*\(/);
  assert.match(block, /event\.message/);
});

test('renderer preserves bounded quarantine inventory counts and exposes a persistent warning', async () => {
  const [source, html, desktopMain] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'),
    fs.readFile(rendererHtmlFile, 'utf8'),
    fs.readFile(desktopMainFile, 'utf8')
  ]);
  const refreshStart = source.indexOf('async function refreshQuarantine');
  const refreshEnd = source.indexOf('\nasync function ', refreshStart + 1);
  const refreshBlock = source.slice(refreshStart, refreshEnd === -1 ? source.length : refreshEnd);
  assert.notEqual(refreshStart, -1, 'quarantine refresh handler is missing');
  assert.match(refreshBlock, /response\?\.items/);
  for (const field of ['total', 'truncatedCount', 'corruptCount', 'oversizedCount']) {
    assert.match(refreshBlock, new RegExp(`response\\?\\.${field}`));
  }

  const renderStart = source.indexOf('function renderQuarantine');
  const renderEnd = source.indexOf('\nfunction ', renderStart + 1);
  const renderBlock = source.slice(renderStart, renderEnd === -1 ? source.length : renderEnd);
  assert.notEqual(renderStart, -1, 'quarantine renderer is missing');
  assert.match(renderBlock, /quarantine-inventory-warning/);
  assert.match(renderBlock, /inventoryWarnings\.join/);
  assert.match(html, /id="quarantine-inventory-warning"[^>]*role="status"/);
  assert.match(html, /id="quarantine-inventory-warning-copy"/);

  const sanitizerStart = desktopMain.indexOf('function sanitizeQuarantineInventory');
  const sanitizerEnd = desktopMain.indexOf('\nfunction ', sanitizerStart + 1);
  const sanitizerBlock = desktopMain.slice(
    sanitizerStart,
    sanitizerEnd === -1 ? desktopMain.length : sanitizerEnd
  );
  assert.notEqual(sanitizerStart, -1, 'quarantine inventory sanitizer is missing');
  assert.match(sanitizerBlock, /hasMore:\s*truncatedCount\s*>\s*0/);
});
