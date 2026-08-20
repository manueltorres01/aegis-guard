import path from 'node:path';

export const IPC_CHANNELS = Object.freeze({
  bootstrap: 'aegis:bootstrap',
  chooseScanTarget: 'aegis:target:choose',
  startScan: 'aegis:scan:start',
  cancelScan: 'aegis:scan:cancel',
  listQuarantine: 'aegis:quarantine:list',
  quarantineIsolate: 'aegis:quarantine:isolate',
  restoreQuarantine: 'aegis:quarantine:restore',
  showQuarantinePath: 'aegis:quarantine:path',
  exportReport: 'aegis:report:export',
  runNetworkAudit: 'aegis:network:audit',
  exportNetworkReport: 'aegis:network:export',
  startMonitor: 'aegis:monitor:start',
  stopMonitor: 'aegis:monitor:stop',
  pauseProtection: 'aegis:protection:pause',
  resumeProtection: 'aegis:protection:resume',
  saveSettings: 'aegis:settings:save',
  createAndScanSimulation: 'aegis:simulation:run',
  checkForUpdates: 'aegis:update:check',
  installUpdate: 'aegis:update:install'
});

export const EVENT_CHANNEL = 'aegis:event';

export const WORKER_PROTOCOL_VERSION = 2;

export const WORKER_ACTIONS = Object.freeze({
  initialize: 'service.initialize',
  bootstrap: 'service.bootstrap',
  startScan: 'scan.start',
  cancelScan: 'scan.cancel',
  listQuarantine: 'quarantine.list',
  isolateResult: 'quarantine.isolate',
  restoreQuarantine: 'quarantine.restore',
  getLatestReport: 'report.latest',
  runNetworkAudit: 'network.audit',
  getLatestNetworkReport: 'network.report.latest',
  startMonitor: 'monitor.start',
  stopMonitor: 'monitor.stop',
  pauseProtection: 'protection.pause',
  resumeProtection: 'protection.resume',
  saveSettings: 'settings.save',
  createAndScanSimulation: 'simulation.run',
  shutdown: 'service.shutdown'
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const THEMES = new Set(['system', 'light', 'dark']);
const UPDATE_CHANNELS = new Set(['stable', 'beta']);

export class ContractError extends Error {
  constructor(message, code = 'INVALID_REQUEST') {
    super(message);
    this.name = 'ContractError';
    this.code = code;
  }
}

export function assertNoPayload(value) {
  if (value !== undefined && value !== null) throw new ContractError('This operation does not accept data');
  return undefined;
}

export function parseChooseTarget(value) {
  if (value === undefined || value === null) return { kind: null, purpose: 'scan' };
  const input = assertPlainObject(value, 'target selection');
  assertOnlyKeys(input, ['kind', 'purpose']);
  const purpose = input.purpose === 'monitor' ? 'monitor' : 'scan';
  const kind = purpose === 'monitor' ? 'directory' : (input.kind ?? null);
  if (kind !== null && !['file', 'directory'].includes(kind)) throw new ContractError('Unknown target type');
  return { kind, purpose };
}

export function parseStartScan(value) {
  const input = assertPlainObject(value, 'scan request');
  assertOnlyKeys(input, ['mode', 'target', 'targetId', 'autoQuarantine']);
  const candidate = input.targetId ?? input.target;
  const requestedMode = input.mode ?? (candidate ? 'deep' : 'quick');
  if (!['quick', 'deep', 'custom', 'full'].includes(requestedMode)) throw new ContractError('Unknown scan mode');
  const mode = requestedMode === 'custom' ? 'deep' : requestedMode;
  const autoQuarantine = parseOptionalBoolean(input.autoQuarantine, 'autoQuarantine');
  if (mode === 'quick' || mode === 'full') {
    if (candidate !== undefined && candidate !== null && candidate !== '') {
      throw new ContractError(`${mode} scans do not accept a target`);
    }
    return { mode, autoQuarantine };
  }
  return { mode, targetId: parseOpaqueId(candidate, 'target identifier'), autoQuarantine };
}

export function parseMonitorStart(value) {
  const input = assertPlainObject(value, 'monitor request');
  assertOnlyKeys(input, ['target', 'targetId', 'autoQuarantine']);
  return {
    targetId: parseOpaqueId(input.targetId ?? input.target, 'target identifier'),
    autoQuarantine: parseOptionalBoolean(input.autoQuarantine, 'autoQuarantine')
  };
}

export function parseRestore(value) {
  const input = assertPlainObject(value, 'restore request');
  assertOnlyKeys(input, ['id']);
  return { id: parseOpaqueId(input.id, 'quarantine identifier') };
}

export const parseQuarantinePath = parseRestore;

export function parseExportReport(value) {
  const input = assertPlainObject(value, 'report export request');
  assertOnlyKeys(input, ['format']);
  if (!['json', 'csv'].includes(input.format)) throw new ContractError('Unknown report format');
  return { format: input.format };
}

export function parseIsolateResult(value) {
  const input = assertPlainObject(value, 'quarantine request');
  assertOnlyKeys(input, ['scanId', 'resultId']);
  return {
    scanId: parseOpaqueId(input.scanId, 'scan identifier'),
    resultId: parseOpaqueId(input.resultId, 'result identifier')
  };
}

export function parseSettings(value) {
  const input = assertPlainObject(value, 'settings');
  assertOnlyKeys(input, ['theme', 'autoQuarantine', 'notifications', 'checkUpdates', 'updateChannel', 'launchAtStartup', 'scheduledScanEnabled', 'scheduledScanMode', 'scheduledScanHour', 'skipScheduledScanOnBattery']);
  const output = {};
  if (Object.hasOwn(input, 'theme')) {
    if (!THEMES.has(input.theme)) throw new ContractError('Unknown theme');
    output.theme = input.theme;
  }
  for (const key of ['autoQuarantine', 'notifications', 'checkUpdates', 'launchAtStartup', 'scheduledScanEnabled', 'skipScheduledScanOnBattery']) {
    if (Object.hasOwn(input, key)) {
      if (typeof input[key] !== 'boolean') throw new ContractError(`${key} must be a boolean`);
      output[key] = input[key];
    }
  }
  if (Object.hasOwn(input, 'updateChannel')) {
    if (!UPDATE_CHANNELS.has(input.updateChannel)) throw new ContractError('Unknown update channel');
    output.updateChannel = input.updateChannel;
  }
  if (Object.hasOwn(input, 'scheduledScanMode')) {
    if (!['quick', 'full'].includes(input.scheduledScanMode)) throw new ContractError('Unknown scheduled scan mode');
    output.scheduledScanMode = input.scheduledScanMode;
  }
  if (Object.hasOwn(input, 'scheduledScanHour')) {
    if (!Number.isSafeInteger(input.scheduledScanHour) || input.scheduledScanHour < 0 || input.scheduledScanHour > 23) throw new ContractError('Invalid scheduled scan hour');
    output.scheduledScanHour = input.scheduledScanHour;
  }
  return output;
}

export function parseOpaqueId(value, label = 'identifier') {
  if (typeof value !== 'string' || !UUID.test(value)) throw new ContractError(`Invalid ${label}`);
  return value.toLowerCase();
}

export function parseWorkerRequest(value) {
  const input = assertPlainObject(value, 'worker message');
  assertOnlyKeys(input, ['kind', 'id', 'action', 'payload']);
  if (input.kind !== 'request') throw new ContractError('Unknown worker message kind');
  const id = parseOpaqueId(input.id, 'request identifier');
  if (!Object.values(WORKER_ACTIONS).includes(input.action)) throw new ContractError('Unknown worker action');
  return { kind: 'request', id, action: input.action, payload: input.payload };
}

export function parseWorkerInitialization(value) {
  const input = assertPlainObject(value, 'service initialization');
  assertOnlyKeys(input, ['baseDirectory', 'dataDirectory', 'downloadsDirectory', 'quarantineKeyBase64']);
  const result = {};
  for (const key of ['baseDirectory', 'dataDirectory', 'downloadsDirectory']) {
    const candidate = input[key];
    if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 32_767 || !path.isAbsolute(candidate)) {
      throw new ContractError(`Invalid ${key}`);
    }
    result[key] = path.resolve(candidate);
  }
  if (!isCanonicalKey(input.quarantineKeyBase64)) throw new ContractError('Invalid quarantine encryption key');
  result.quarantineKeyBase64 = input.quarantineKeyBase64;
  return result;
}

export function parseWorkerActionPayload(action, value) {
  switch (action) {
    case WORKER_ACTIONS.initialize:
      return parseWorkerInitialization(value);
    case WORKER_ACTIONS.bootstrap:
    case WORKER_ACTIONS.cancelScan:
    case WORKER_ACTIONS.listQuarantine:
    case WORKER_ACTIONS.stopMonitor:
    case WORKER_ACTIONS.pauseProtection:
    case WORKER_ACTIONS.resumeProtection:
    case WORKER_ACTIONS.createAndScanSimulation:
    case WORKER_ACTIONS.runNetworkAudit:
    case WORKER_ACTIONS.shutdown:
      return assertEmptyObjectOrUndefined(value);
    case WORKER_ACTIONS.getLatestReport: {
      const input = assertPlainObject(value, 'latest report request');
      assertOnlyKeys(input, ['format']);
      if (!['json', 'csv'].includes(input.format)) throw new ContractError('Unknown report format');
      return { format: input.format };
    }
    case WORKER_ACTIONS.getLatestNetworkReport: {
      const input = assertPlainObject(value, 'latest network report request');
      assertOnlyKeys(input, ['format']);
      if (!['json', 'csv'].includes(input.format)) throw new ContractError('Unknown network report format');
      return { format: input.format };
    }
    case WORKER_ACTIONS.startScan: {
      const input = assertPlainObject(value, 'worker scan request');
      assertOnlyKeys(input, ['mode', 'target', 'autoQuarantine']);
      const requestedMode = input.mode ?? (input.target === 'quick' ? 'quick' : 'deep');
      if (!['quick', 'deep', 'custom', 'full'].includes(requestedMode)) throw new ContractError('Unknown worker scan mode');
      const mode = requestedMode === 'custom' ? 'deep' : requestedMode;
      if (mode === 'full' && input.target !== undefined) throw new ContractError('Full scans do not accept a target');
      if (mode === 'quick' && input.target !== 'quick') throw new ContractError('Quick scans require the internal quick target');
      if (mode === 'deep' && input.target === undefined) throw new ContractError('Deep scans require a target');
      return {
        mode,
        target: mode === 'full' ? undefined : mode === 'quick' ? 'quick' : parseAbsolutePath(input.target, 'scan target'),
        autoQuarantine: parseOptionalBoolean(input.autoQuarantine, 'autoQuarantine')
      };
    }
    case WORKER_ACTIONS.restoreQuarantine: {
      const input = assertPlainObject(value, 'worker restore request');
      assertOnlyKeys(input, ['id', 'destination']);
      return {
        id: parseOpaqueId(input.id, 'quarantine identifier'),
        destination: parseAbsolutePath(input.destination, 'restore destination')
      };
    }
    case WORKER_ACTIONS.isolateResult: {
      const input = assertPlainObject(value, 'worker quarantine request');
      assertOnlyKeys(input, ['scanId', 'resultId']);
      return {
        scanId: parseOpaqueId(input.scanId, 'scan identifier'),
        resultId: parseOpaqueId(input.resultId, 'result identifier')
      };
    }
    case WORKER_ACTIONS.startMonitor: {
      const input = assertPlainObject(value, 'worker monitor request');
      assertOnlyKeys(input, ['target', 'autoQuarantine']);
      return {
        target: parseAbsolutePath(input.target, 'monitor target'),
        autoQuarantine: parseOptionalBoolean(input.autoQuarantine, 'autoQuarantine')
      };
    }
    case WORKER_ACTIONS.saveSettings:
      return parseSettings(value);
    default:
      throw new ContractError('Unsupported worker action');
  }
}

export function serializeError(error, { includeDetails = false } = {}) {
  const message = typeof error?.message === 'string' && error.message.length > 0
    ? error.message.slice(0, 1_000)
    : 'Unexpected error';
  const output = {
    code: typeof error?.code === 'string' ? error.code.slice(0, 80) : 'OPERATION_FAILED',
    message
  };
  if (includeDetails && typeof error?.stack === 'string') output.stack = error.stack.slice(0, 8_000);
  return output;
}

function parseAbsolutePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 32_767 || !path.isAbsolute(value)) {
    throw new ContractError(`Invalid ${label}`);
  }
  return path.resolve(value);
}

function parseOptionalBoolean(value, label) {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new ContractError(`${label} must be a boolean`);
  return value;
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ContractError(`Invalid ${label}`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new ContractError(`Invalid ${label}`);
  return value;
}

function assertOnlyKeys(input, allowed) {
  const allowedKeys = new Set(allowed);
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) throw new ContractError(`Unknown field: ${key}`);
  }
}

function assertEmptyObjectOrUndefined(value) {
  if (value === undefined || value === null) return undefined;
  const input = assertPlainObject(value, 'empty request');
  assertOnlyKeys(input, []);
  return undefined;
}

function isCanonicalKey(value) {
  if (typeof value !== 'string' || value.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === 32 && decoded.toString('base64') === value;
}
