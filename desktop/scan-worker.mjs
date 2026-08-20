import {
  WORKER_ACTIONS,
  WORKER_PROTOCOL_VERSION,
  parseWorkerActionPayload,
  parseWorkerRequest,
  serializeError
} from './ipc-contracts.mjs';
import { AppService } from '../src/app-service.mjs';

const MAX_REPORT_RESULTS = 5_000;
const parentPort = process.parentPort;

if (!parentPort) throw new Error('Aegis scan worker must be started as an Electron utility process');

let service = null;
let shuttingDown = false;
let activeLongOperation = null;

parentPort.on('message', event => {
  const data = event?.data ?? event;
  void handleMessage(data);
});

post({ kind: 'ready', protocolVersion: WORKER_PROTOCOL_VERSION });

async function handleMessage(raw) {
  let request;
  try {
    request = parseWorkerRequest(raw);
    const payload = parseWorkerActionPayload(request.action, request.payload);
    const result = await dispatch(request.action, payload);
    post({ kind: 'response', id: request.id, ok: true, result: limitLargeReports(result) });
  } catch (error) {
    post({
      kind: 'response',
      id: request?.id ?? null,
      ok: false,
      error: serializeError(error)
    });
  }
}

async function dispatch(action, payload) {
  if (action === WORKER_ACTIONS.initialize) {
    if (service) throw operationError('ALREADY_INITIALIZED', 'The scan service is already initialized');
    service = new AppService({
      ...payload,
      emit: event => post({ kind: 'event', event: limitLargeReports(event) })
    });
    return service.init();
  }

  if (!service) throw operationError('NOT_INITIALIZED', 'The scan service is not initialized');

  switch (action) {
    case WORKER_ACTIONS.bootstrap:
      return service.getBootstrap();
    case WORKER_ACTIONS.startScan:
      return runLongOperation(() => service.startScan({
        mode: payload.mode,
        target: payload.target,
        autoQuarantine: payload.autoQuarantine
      }));
    case WORKER_ACTIONS.cancelScan:
      return { cancelled: Boolean(service.cancelScan()) };
    case WORKER_ACTIONS.listQuarantine:
      return service.listQuarantine();
    case WORKER_ACTIONS.getLatestReport:
      return service.getLatestReport(payload.format);
    case WORKER_ACTIONS.runNetworkAudit:
      return service.runNetworkAudit();
    case WORKER_ACTIONS.getLatestNetworkReport:
      return service.getLatestNetworkReport(payload.format);
    case WORKER_ACTIONS.isolateResult:
      return service.isolateResult(payload.scanId, payload.resultId);
    case WORKER_ACTIONS.restoreQuarantine:
      return service.restoreQuarantine(payload.id, payload.destination);
    case WORKER_ACTIONS.startMonitor:
      return service.startMonitor(payload.target, { autoQuarantine: payload.autoQuarantine });
    case WORKER_ACTIONS.stopMonitor:
      return service.stopMonitor();
    case WORKER_ACTIONS.pauseProtection:
      return service.pauseProtection();
    case WORKER_ACTIONS.resumeProtection:
      return service.resumeProtection();
    case WORKER_ACTIONS.saveSettings:
      return service.saveSettings(payload);
    case WORKER_ACTIONS.createAndScanSimulation:
      return runLongOperation(() => service.createAndScanSimulation());
    case WORKER_ACTIONS.shutdown:
      shuttingDown = true;
      await service.shutdown();
      if (activeLongOperation) await activeLongOperation.catch(() => {});
      return { stopped: true };
    default:
      throw operationError('UNKNOWN_ACTION', 'Unknown scan service action');
  }
}

async function runLongOperation(start) {
  if (activeLongOperation) throw operationError('SCAN_BUSY', 'A scan is already running');
  const operation = Promise.resolve().then(start);
  activeLongOperation = operation;
  try {
    return await operation;
  } finally {
    if (activeLongOperation === operation) activeLongOperation = null;
  }
}

function limitLargeReports(value) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    const trimmed = value.slice(0, MAX_REPORT_RESULTS).map(limitLargeReports);
    if (value.length > MAX_REPORT_RESULTS) {
      Object.defineProperty(trimmed, 'truncatedCount', {
        value: value.length - MAX_REPORT_RESULTS,
        enumerable: true
      });
    }
    return trimmed;
  }

  const output = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'results' && Array.isArray(item) && item.length > MAX_REPORT_RESULTS) {
      output.results = item.slice(0, MAX_REPORT_RESULTS).map(limitLargeReports);
      output.resultsTruncated = item.length - MAX_REPORT_RESULTS;
    } else {
      output[key] = limitLargeReports(item);
    }
  }
  return output;
}

function post(message) {
  if (shuttingDown && message.kind === 'event') return;
  parentPort.postMessage(message);
}

function operationError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
