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

test('0.5.0 exposes ransomware monitoring only as audit mode', async () => {
  const [html, app, main] = await Promise.all([
    fs.readFile(new URL('../desktop/renderer/index.html', import.meta.url), 'utf8'),
    fs.readFile(new URL('../desktop/renderer/app.js', import.meta.url), 'utf8'),
    fs.readFile(new URL('../desktop/main.mjs', import.meta.url), 'utf8')
  ]);
  assert.match(html, /id="ransomware-audit-enabled"/);
  assert.match(html, /No bloquea procesos ni atribuye autores/);
  assert.match(app, /Actividad compatible con ransomware/);
  assert.match(app, /no ha bloqueado ningún proceso/);
  assert.match(main, /action: 'observed-only'/);
  assert.doesNotMatch(html, /Bloquear ransomware automáticamente/);
});

test('0.5.1 exposes bounded performance diagnostics without changing scan scope', async () => {
  const [app, main, roadmap] = await Promise.all([
    fs.readFile(new URL('../desktop/renderer/app.js', import.meta.url), 'utf8'),
    fs.readFile(new URL('../desktop/main.mjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../docs/ROADMAP.md', import.meta.url), 'utf8')
  ]);
  assert.match(app, /health-performance/);
  assert.match(app, /performance: \{engine:/);
  assert.match(main, /function sanitizePerformance/);
  assert.match(roadmap, /0\.5\.1 — Resource-efficient scanning/);
});

test('0.6.0 exposes read-only local EDR audit with explainable MITRE evidence', async () => {
  const [app, html, main, contracts, preload, roadmap, usage] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'), fs.readFile(rendererHtmlFile, 'utf8'), fs.readFile(desktopMainFile, 'utf8'),
    fs.readFile(new URL('../desktop/ipc-contracts.mjs', import.meta.url), 'utf8'), fs.readFile(new URL('../desktop/preload.cjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../docs/ROADMAP.md', import.meta.url), 'utf8'), fs.readFile(new URL('../docs/DESKTOP-USAGE.md', import.meta.url), 'utf8')
  ]);
  for (const marker of ['data-view="incidents"', 'id="run-edr-audit"', 'id="export-edr-report"', 'id="edr-body"']) assert.match(html, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(app, /runEdrAudit/);
  assert.match(app, /T1059\.001/);
  assert.match(main, /function sanitizeEdrReport/);
  assert.match(main, /terminationAvailable:false/);
  assert.match(contracts, /edr\.audit/);
  assert.match(preload, /runEdrAudit/);
  assert.match(roadmap, /0\.6\.0 — Behavioral detection and local EDR/);
  assert.match(usage, /Local EDR audit/);
  assert.doesNotMatch(html, /Terminar proceso/);
});

test('0.7.0 keeps network protection explicit, reversible and IP-scoped', async () => {
  const [app, html, main, contracts, preload, protection, roadmap, usage] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'), fs.readFile(rendererHtmlFile, 'utf8'), fs.readFile(desktopMainFile, 'utf8'),
    fs.readFile(new URL('../desktop/ipc-contracts.mjs', import.meta.url), 'utf8'), fs.readFile(new URL('../desktop/preload.cjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../src/network-protection.mjs', import.meta.url), 'utf8'), fs.readFile(new URL('../docs/ROADMAP.md', import.meta.url), 'utf8'), fs.readFile(new URL('../docs/DESKTOP-USAGE.md', import.meta.url), 'utf8')
  ]);
  for (const id of ['network-protection-mode', 'apply-network-protection', 'remove-network-protection', 'network-anomaly-summary']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /applyNetworkProtection/);
  assert.match(app, /networkProtectionMode/);
  assert.match(main, /function sanitizeNetworkProtection/);
  assert.match(contracts, /network\.protection\.apply/);
  assert.match(preload, /removeNetworkProtection/);
  assert.match(protection, /New-NetFirewallRule/);
  assert.match(protection, /Aegis Guard 0\.7\.0 Indicators/);
  assert.match(protection, /operation === 'remove'/);
  assert.match(roadmap, /0\.7\.0 — Enforced network and web protection/);
  assert.match(usage, /Protección de red reversible/);
  assert.match(html, /Modo auditoría por defecto/);
  assert.doesNotMatch(html, /Aislar toda la red automáticamente/);
});

test('0.8.0 exposes read-only device and application exposure inventory', async () => {
  const [app, html, main, contracts, preload, roadmap, usage, policies] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'), fs.readFile(rendererHtmlFile, 'utf8'), fs.readFile(desktopMainFile, 'utf8'),
    fs.readFile(new URL('../desktop/ipc-contracts.mjs', import.meta.url), 'utf8'), fs.readFile(new URL('../desktop/preload.cjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../docs/ROADMAP.md', import.meta.url), 'utf8'), fs.readFile(new URL('../docs/DESKTOP-USAGE.md', import.meta.url), 'utf8'),
    fs.readFile(new URL('../definitions/application-policies.json', import.meta.url), 'utf8')
  ]);
  for (const id of ['data-view="exposure"', 'id="run-exposure-audit"', 'id="export-exposure-json"', 'id="export-exposure-csv"', 'id="exposure-body"']) assert.match(html, new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(app, /runExposureAudit/);
  assert.match(app, /exportExposureReport/);
  assert.match(main, /function sanitizeExposureReport/);
  assert.match(contracts, /exposure\.audit/);
  assert.match(preload, /runExposureAudit/);
  assert.match(roadmap, /0\.8\.0/);
  assert.match(usage, /exposición/i);
  assert.equal(JSON.parse(policies).mode, 'audit');
  assert.doesNotMatch(html, /Bloquear USB/);
});

test('0.9.0 exposes bounded self-protection audit and explicit reputation consent', async () => {
  const [app, html, main, contracts, preload, roadmap, usage] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'), fs.readFile(rendererHtmlFile, 'utf8'), fs.readFile(desktopMainFile, 'utf8'),
    fs.readFile(new URL('../desktop/ipc-contracts.mjs', import.meta.url), 'utf8'), fs.readFile(new URL('../desktop/preload.cjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../docs/ROADMAP.md', import.meta.url), 'utf8'), fs.readFile(new URL('../docs/DESKTOP-USAGE.md', import.meta.url), 'utf8')
  ]);
  for (const id of ['data-view="integrity"', 'id="run-integrity-audit"', 'id="export-integrity-json"', 'id="export-integrity-csv"', 'id="reputation-sharing-enabled"']) assert.match(html, new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(app, /runIntegrityAudit/);
  assert.match(app, /reputationSharingEnabled/);
  assert.match(main, /function sanitizeIntegrityReport/);
  assert.match(contracts, /integrity\.audit/);
  assert.match(preload, /exportIntegrityReport/);
  assert.match(roadmap, /0\.9\.0/);
  assert.match(usage, /integridad/i);
  assert.match(usage, /retención/i);
  assert.doesNotMatch(html, /Reparar automáticamente/);
});

test('0.10.0 exposes signed definition import and reversible rollback controls', async () => {
  const [app, html, main, contracts, preload, roadmap] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'), fs.readFile(rendererHtmlFile, 'utf8'), fs.readFile(desktopMainFile, 'utf8'),
    fs.readFile(new URL('../desktop/ipc-contracts.mjs', import.meta.url), 'utf8'), fs.readFile(new URL('../desktop/preload.cjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../docs/ROADMAP.md', import.meta.url), 'utf8')
  ]);
  for (const id of ['import-definition-bundle', 'rollback-definitions', 'definition-update-version']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /importDefinitionBundle/);
  assert.match(app, /rollbackDefinitions/);
  assert.match(main, /function importDefinitionBundle/);
  assert.match(contracts, /definitions\.apply/);
  assert.match(preload, /importDefinitionBundle/);
  assert.match(roadmap, /0\.10\.0/);
  assert.doesNotMatch(html, /Actualizar definiciones sin verificar/);
});

test('0.11.0 exposes explicit hash-only threat intelligence lookups', async () => {
  const [app, html, main, contracts, preload, roadmap, usage] = await Promise.all([
    fs.readFile(rendererFile, 'utf8'), fs.readFile(rendererHtmlFile, 'utf8'), fs.readFile(desktopMainFile, 'utf8'),
    fs.readFile(new URL('../desktop/ipc-contracts.mjs', import.meta.url), 'utf8'), fs.readFile(new URL('../desktop/preload.cjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../docs/ROADMAP.md', import.meta.url), 'utf8'), fs.readFile(new URL('../docs/DESKTOP-USAGE.md', import.meta.url), 'utf8')
  ]);
  assert.match(html, /id="reputation-sharing-enabled"/);
  assert.match(app, /queryThreatIntel/);
  assert.match(app, /Solo SHA-256|SHA-256/);
  assert.match(main, /sanitizeThreatIntelResult/);
  assert.match(contracts, /threat-intel\.query/);
  assert.match(preload, /queryThreatIntel/);
  assert.match(roadmap, /0\.11\.0/);
  assert.match(usage, /CIRCL Hash Lookup/i);
  assert.match(usage, /nunca sube el archivo/i);
  assert.match(html, /id="check-definition-feed"/);
  assert.match(app, /checkDefinitionFeed/);
  assert.match(main, /definitions-feed-warning/);
  assert.match(contracts, /definitions\.feed\.check/);
  assert.match(preload, /checkDefinitionFeed/);
});
