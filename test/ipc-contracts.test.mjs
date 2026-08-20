import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  ContractError,
  WORKER_ACTIONS,
  parseExportReport,
  parseIsolateResult,
  parseMonitorStart,
  parseSettings,
  parseStartScan,
  parseWorkerActionPayload,
  parseWorkerInitialization
} from '../desktop/ipc-contracts.mjs';

const targetId = '76d2809c-2614-45df-908f-587506ab3949';
const resultId = '182452d6-a237-4a12-9552-f29849535227';

test('renderer scan contracts normalize deep/custom and reject paths or misplaced targets', () => {
  assert.deepEqual(parseStartScan({ mode: 'quick' }), { mode: 'quick', autoQuarantine: undefined });
  assert.deepEqual(parseStartScan({ mode: 'deep', targetId }), {
    mode: 'deep', targetId, autoQuarantine: undefined
  });
  assert.deepEqual(parseStartScan({ mode: 'custom', targetId }), {
    mode: 'deep', targetId, autoQuarantine: undefined
  });
  assert.deepEqual(parseStartScan({ mode: 'full' }), { mode: 'full', autoQuarantine: undefined });
  assert.throws(() => parseStartScan({ mode: 'deep' }), ContractError);
  assert.throws(() => parseStartScan({ mode: 'deep', targetId: 'C:\\Windows' }), ContractError);
  assert.throws(() => parseStartScan({ mode: 'deep', path: 'C:\\Windows' }), ContractError);
  assert.throws(() => parseStartScan({ mode: 'quick', path: 'C:\\Windows' }), ContractError);
  assert.throws(() => parseStartScan({ mode: 'quick', targetId }), ContractError);
  assert.throws(() => parseStartScan({ mode: 'full', targetId }), ContractError);
});

test('worker scan contract accepts absolute deep targets and keeps quick/full target-free externally', () => {
  const internalTarget = path.resolve('selected-scan-root');
  assert.deepEqual(
    parseWorkerActionPayload(WORKER_ACTIONS.startScan, {
      mode: 'deep', target: internalTarget, autoQuarantine: false
    }),
    { mode: 'deep', target: internalTarget, autoQuarantine: false }
  );
  assert.deepEqual(
    parseWorkerActionPayload(WORKER_ACTIONS.startScan, {
      mode: 'custom', target: internalTarget
    }),
    { mode: 'deep', target: internalTarget, autoQuarantine: undefined }
  );
  assert.deepEqual(
    parseWorkerActionPayload(WORKER_ACTIONS.startScan, { mode: 'quick', target: 'quick' }),
    { mode: 'quick', target: 'quick', autoQuarantine: undefined }
  );
  assert.deepEqual(
    parseWorkerActionPayload(WORKER_ACTIONS.startScan, { mode: 'full' }),
    { mode: 'full', target: undefined, autoQuarantine: undefined }
  );
  assert.throws(
    () => parseWorkerActionPayload(WORKER_ACTIONS.startScan, { mode: 'deep' }),
    ContractError
  );
  assert.throws(
    () => parseWorkerActionPayload(WORKER_ACTIONS.startScan, { mode: 'deep', target: 'relative' }),
    ContractError
  );
  assert.throws(
    () => parseWorkerActionPayload(WORKER_ACTIONS.startScan, { mode: 'quick', target: internalTarget }),
    ContractError
  );
  assert.throws(
    () => parseWorkerActionPayload(WORKER_ACTIONS.startScan, { mode: 'full', target: internalTarget }),
    ContractError
  );
});

test('settings contract accepts only a boolean launchAtStartup value', () => {
  assert.deepEqual(parseSettings({ launchAtStartup: true }), { launchAtStartup: true });
  assert.deepEqual(parseSettings({ launchAtStartup: false }), { launchAtStartup: false });
  assert.throws(() => parseSettings({ launchAtStartup: 'true' }), ContractError);
});

test('scheduled scan settings are bounded and battery-safe', () => {
  assert.deepEqual(parseSettings({scheduledScanEnabled:true,scheduledScanMode:'full',scheduledScanHour:23,skipScheduledScanOnBattery:true}), {scheduledScanEnabled:true,scheduledScanMode:'full',scheduledScanHour:23,skipScheduledScanOnBattery:true});
  assert.throws(() => parseSettings({scheduledScanMode:'deep'}), ContractError);
  assert.throws(() => parseSettings({scheduledScanHour:24}), ContractError);
  assert.throws(() => parseSettings({skipScheduledScanOnBattery:'yes'}), ContractError);
});

test('ransomware audit setting is an explicit boolean only', () => {
  assert.deepEqual(parseSettings({ ransomwareAuditEnabled: true }), { ransomwareAuditEnabled: true });
  assert.deepEqual(parseSettings({ ransomwareAuditEnabled: false }), { ransomwareAuditEnabled: false });
  assert.throws(() => parseSettings({ ransomwareAuditEnabled: 'audit' }), ContractError);
});

test('report export contracts accept only JSON and CSV', () => {
  assert.deepEqual(parseExportReport({ format: 'json' }), { format: 'json' });
  assert.deepEqual(parseWorkerActionPayload(WORKER_ACTIONS.getLatestReport, { format: 'csv' }), { format: 'csv' });
  assert.throws(() => parseExportReport({ format: 'html' }), ContractError);
  assert.throws(() => parseExportReport({ format: 'json', path: 'C:\\outside.json' }), ContractError);
});

test('monitor and manual quarantine contracts require strict opaque identifiers', () => {
  assert.deepEqual(parseMonitorStart({ targetId, autoQuarantine: false }), { targetId, autoQuarantine: false });
  assert.deepEqual(parseIsolateResult({ scanId: targetId, resultId }), { scanId: targetId, resultId });
  assert.throws(() => parseMonitorStart({ targetId: '../outside' }), ContractError);
  assert.throws(() => parseIsolateResult({ scanId: targetId, resultId, path: 'C:\\Windows\\system.ini' }), ContractError);
});

test('worker initialization requires absolute internal paths and a canonical 32-byte key', () => {
  const key = Buffer.alloc(32, 7).toString('base64');
  const parsed = parseWorkerInitialization({
    baseDirectory: 'C:\\Aegis',
    dataDirectory: 'C:\\Users\\Demo\\AppData\\Local\\Aegis',
    downloadsDirectory: 'C:\\Users\\Demo\\Downloads',
    quarantineKeyBase64: key
  });
  assert.equal(parsed.quarantineKeyBase64, key);
  assert.deepEqual(parsed.protectedDirectories, []);
  const protectedDirectory = 'C:\\Users\\Demo\\Documents';
  assert.deepEqual(parseWorkerInitialization({
    baseDirectory: 'C:\\Aegis', dataDirectory: 'C:\\Data', downloadsDirectory: 'C:\\Downloads',
    protectedDirectories: [protectedDirectory], quarantineKeyBase64: key
  }).protectedDirectories, [protectedDirectory]);
  assert.throws(() => parseWorkerInitialization({
    baseDirectory: 'C:\\Aegis', dataDirectory: 'C:\\Data', downloadsDirectory: 'C:\\Downloads',
    protectedDirectories: ['relative'], quarantineKeyBase64: key
  }), ContractError);
  assert.throws(() => parseWorkerInitialization({
    baseDirectory: '.', dataDirectory: 'data', downloadsDirectory: 'downloads', quarantineKeyBase64: key
  }), ContractError);
  assert.throws(() => parseWorkerInitialization({
    baseDirectory: 'C:\\Aegis', dataDirectory: 'C:\\Data', downloadsDirectory: 'C:\\Downloads',
    quarantineKeyBase64: Buffer.alloc(31).toString('base64')
  }), ContractError);
});
