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

test('results expose exact 0.2.2 filters, native report export, and original-path restore', async () => {
  const [source, html, desktopMain] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'),
    fs.readFile(rendererHtmlFile, 'utf8'),
    fs.readFile(desktopMainFile, 'utf8')
  ]);
  for (const filter of ['all', 'suspicious', 'not-scanned', 'malicious']) {
    assert.match(html, new RegExp(`data-filter="${filter}"`));
  }
  assert.match(html, /id="export-report-json"/);
  assert.match(html, /id="export-report-csv"/);
  assert.match(source, /callApi\('exportReport'/);

  const restoreStart = desktopMain.indexOf('async function restoreQuarantine');
  const restoreEnd = desktopMain.indexOf('\nasync function ', restoreStart + 1);
  const restoreBlock = desktopMain.slice(restoreStart, restoreEnd);
  assert.match(restoreBlock, /metadata\.originalPath/);
  assert.doesNotMatch(restoreBlock, /showSaveDialog/);
});

test('0.2.3 exposes bounded network audit and report export without block controls', async () => {
  const [source, html] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'),
    fs.readFile(rendererHtmlFile, 'utf8')
  ]);
  assert.match(html, /data-view="network"/);
  assert.match(html, /id="run-network-audit"/);
  assert.match(html, /id="export-network-json"/);
  assert.match(html, /Modo auditoría/);
  assert.doesNotMatch(html, /Bloquear conexión/);
  assert.match(source, /runNetworkAudit/);
  assert.match(source, /exportNetworkReport/);
});

test('0.3.0 quarantine exposes a path action and restores only to the original location', async () => {
  const [source, desktopMain, preload] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'), fs.readFile(desktopMainFile, 'utf8'),
    fs.readFile(new URL('../desktop/preload.cjs', import.meta.url), 'utf8')
  ]);
  assert.match(source, /showPath\.textContent = 'Ruta'/);
  assert.match(source, /restore\.textContent = 'Restaurar'/);
  assert.match(preload, /showQuarantinePath/);
  const restoreStart = desktopMain.indexOf('async function restoreQuarantine');
  const restoreEnd = desktopMain.indexOf('\nasync function ', restoreStart + 1);
  assert.match(desktopMain.slice(restoreStart, restoreEnd), /metadata\.originalPath/);
  assert.doesNotMatch(desktopMain.slice(restoreStart, restoreEnd), /showSaveDialog/);
});

test('0.3.0 exposes background tray, authenticated diagnostics and scheduled scan controls', async () => {
  const [source, html, desktopMain] = await Promise.all([fs.readFile(rendererFile,'utf8'),fs.readFile(rendererHtmlFile,'utf8'),fs.readFile(desktopMainFile,'utf8')]);
  for (const id of ['scheduled-scan-enabled','scheduled-scan-mode','scheduled-scan-hour','scheduled-scan-battery','health-summary']) assert.match(html,new RegExp(`id="${id}"`));
  assert.match(source,/syncScheduleSettings/);
  assert.match(desktopMain,/new Tray/);
  assert.match(desktopMain,/checkScheduledScan/);
  assert.match(desktopMain,/powerMonitor\.isOnBatteryPower/);
  assert.match(desktopMain,/signWorkerMessage/);
});

test('0.4.0 presents PUA separately from confirmed malware', async () => {
  const app = await fs.readFile(new URL('../desktop/renderer/app.js', import.meta.url), 'utf8');
  assert.match(app, /classification === 'pua'/);
  assert.match(app, /Aplicación no deseada/);
});

test('packaged tray uses a supported PNG and fails open to the main window', async () => {
  const main = await fs.readFile(new URL('../desktop/main.mjs', import.meta.url), 'utf8');
  const builder = await fs.readFile(new URL('../electron-builder.yml', import.meta.url), 'utf8');
  assert.match(main, /build', 'icon\.png'/);
  assert.match(main, /catch \{ tray = null; return false; \}/);
  assert.match(main, /if \(!tray\) \{ isQuitting = true; return; \}/);
  assert.match(builder, /build\/icon\.png/);
});
