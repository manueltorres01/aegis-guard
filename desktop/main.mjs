import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  app,
  BrowserWindow,
  Menu,
  Tray,
  dialog,
  ipcMain,
  powerMonitor,
  protocol,
  safeStorage,
  screen,
  session,
  utilityProcess
} from 'electron';
import {
  ContractError,
  EVENT_CHANNEL,
  IPC_CHANNELS,
  WORKER_ACTIONS,
  WORKER_PROTOCOL_VERSION,
  assertNoPayload,
  parseChooseTarget,
  parseExportReport,
  parseIsolateResult,
  parseMonitorStart,
  parseRestore,
  parseQuarantinePath,
  parseSettings,
  parseStartScan,
  serializeError
} from './ipc-contracts.mjs';
import { UpdateService } from './update-service.mjs';
import { TargetVault } from './target-vault.mjs';
import { signWorkerMessage, verifyWorkerMessage } from './ipc-auth.mjs';

const APPLICATION_ORIGIN = 'aegis://app';
const APPLICATION_ENTRY = `${APPLICATION_ORIGIN}/index.html`;
const APPLICATION_PARTITION = 'persist:aegis-guard';
const APPLICATION_ID = 'io.github.manueltorres01.aegisguard';
const RENDERER_DIRECTORY = fileURLToPath(new URL('./renderer/', import.meta.url));
const WORKER_FILE = fileURLToPath(new URL('./scan-worker.mjs', import.meta.url));
const PRELOAD_FILE = fileURLToPath(new URL('./preload.cjs', import.meta.url));

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'none'",
  "connect-src 'none'",
  "font-src 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "img-src 'self' data:",
  "media-src 'none'",
  "object-src 'none'",
  "script-src 'self'",
  "style-src 'self'"
].join('; ');

protocol.registerSchemesAsPrivileged([{
  scheme: 'aegis',
  privileges: {
    standard: true,
    secure: true,
    supportFetchAPI: true,
    corsEnabled: false,
    stream: true
  }
}]);

const hasInstanceLock = app.requestSingleInstanceLock();
let mainWindow = null;
let engine = null;
let updateService = null;
let isQuitting = false;
let shutdownStarted = false;
let activeScanContext = null;
let activeMonitorContext = null;
let activeMutationCount = 0;
let backgroundLaunch = false;
let startupRequested = true;
let startupError = null;
let tray = null;
let scheduledSettings = null;
let scheduledTimer = null;
let lastScheduledDay = null;
const targetVault = new TargetVault();

if (!hasInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', (_event, commandLine) => {
    if (commandLine.includes('--background')) return;
    if (!mainWindow || mainWindow.isDestroyed()) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });

  app.on('before-quit', event => {
    if (shutdownStarted) return;
    event.preventDefault();
    shutdownStarted = true;
    isQuitting = true;
    void gracefulShutdown().finally(() => app.quit());
  });

  app.on('window-all-closed', () => {});

  app.on('activate', () => {
    if (!mainWindow && engine) void createMainWindow();
  });

  void startApplication().catch(async error => {
    const details = serializeError(error);
    await dialog.showMessageBox({
      type: 'error',
      title: 'Aegis Guard',
      message: 'Aegis Guard no pudo iniciar de forma segura.',
      detail: details.message
    });
    app.quit();
  });
}

async function gracefulShutdown() {
  if (scheduledTimer) { clearInterval(scheduledTimer); scheduledTimer = null; }
  if (!engine) return;
  try { await engine.shutdown(); }
  catch { /* a forced stop below is the fail-safe */ }
  finally { engine.dispose(); }
}

async function startApplication() {
  await app.whenReady();
  app.setAppUserModelId(APPLICATION_ID);
  backgroundLaunch = app.isPackaged && process.platform === 'win32' && process.argv.includes('--background');

  const quarantineKey = await loadQuarantineKey();

  const applicationSession = session.fromPartition(APPLICATION_PARTITION);
  registerLocalProtocol(applicationSession);
  hardenSession(applicationSession);

  engine = new EngineBridge(event => publishEvent(sanitizeWorkerEvent(event)));
  const initialBootstrap = await engine.start({
    baseDirectory: app.getAppPath(),
    dataDirectory: app.getPath('userData'),
    downloadsDirectory: app.getPath('downloads'),
    quarantineKeyBase64: quarantineKey.value
  });
  scheduledSettings = sanitizeSettings(initialBootstrap?.settings);
  lastScheduledDay = await loadScheduledDay();
  applyLaunchAtStartup(initialBootstrap?.settings?.launchAtStartup !== false);

  updateService = new UpdateService({
    app,
    publish: publishEvent,
    isBusy: () => Boolean(activeScanContext || activeMutationCount)
  });
  await updateService.initialize();

  registerIpcHandlers();
  createTray();
  startScheduleLoop();
  await createMainWindow(applicationSession);
  if (quarantineKey.developmentFallback) {
    void dialog.showMessageBox(mainWindow, {
      type: 'warning',
      title: 'Protección de desarrollo',
      message: 'DPAPI no está disponible en este entorno de desarrollo.',
      detail: 'La clave local de cuarentena se ha guardado con permisos restringidos. Las compilaciones distribuidas no permiten este fallback.'
    });
  }
}

function startScheduleLoop() {
  if (scheduledTimer) clearInterval(scheduledTimer);
  scheduledTimer = setInterval(() => void checkScheduledScan(), 60_000);
  scheduledTimer.unref?.();
  void checkScheduledScan();
}

async function checkScheduledScan(now = new Date()) {
  const settings = scheduledSettings;
  if (!settings?.scheduledScanEnabled || activeScanContext || now.getHours() !== settings.scheduledScanHour) return false;
  const day = now.toISOString().slice(0, 10);
  if (lastScheduledDay === day) return false;
  if (settings.skipScheduledScanOnBattery && powerMonitor.isOnBatteryPower()) return false;
  const mode = settings.scheduledScanMode === 'full' ? 'full' : 'quick';
  const context = mode === 'full' ? fullTargetContext() : quickTargetContext();
  activeScanContext = context;
  lastScheduledDay = day;
  await saveScheduledDay(day).catch(() => {});
  try {
    await engine.request(WORKER_ACTIONS.startScan, { mode, target: mode === 'quick' ? 'quick' : undefined, autoQuarantine: settings.autoQuarantine }, { timeoutMs: 0 });
    return true;
  } catch (error) {
    publishEvent({ type:'scan-warning', payload:{ code:'SCHEDULED_SCAN_FAILED', message:error?.message ?? 'El análisis programado no pudo completarse.' } });
    return false;
  } finally { activeScanContext = null; }
}

async function loadScheduledDay() {
  try {
    const value = JSON.parse(await fs.readFile(path.join(app.getPath('userData'), 'schedule-state.json'), 'utf8'));
    return typeof value?.day === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value.day) ? value.day : null;
  } catch { return null; }
}

async function saveScheduledDay(day) {
  const file = path.join(app.getPath('userData'), 'schedule-state.json');
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(temporary, JSON.stringify({ day }), { flag:'wx', mode:0o600 });
  await fs.rename(temporary, file);
}

function createTray() {
  if (tray || process.platform !== 'win32') return Boolean(tray);
  try { tray = new Tray(path.join(app.getAppPath(), 'build', 'icon.png')); }
  catch { tray = null; return false; }
  tray.setToolTip('Aegis Guard · protección activa');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Abrir Aegis Guard', click: () => { if (mainWindow && !mainWindow.isDestroyed()) { mainWindow.show(); mainWindow.focus(); } } },
    { type: 'separator' },
    { label: 'Salir y detener protección', click: () => { isQuitting = true; app.quit(); } }
  ]));
  tray.on('double-click', () => { if (mainWindow && !mainWindow.isDestroyed()) { mainWindow.show(); mainWindow.focus(); } });
  return true;
}

function applyLaunchAtStartup(requested) {
  startupRequested = Boolean(requested);
  startupError = null;
  if (!isStartupSupported()) return startupPublicState();
  try {
    app.setLoginItemSettings({
      openAtLogin: startupRequested,
      path: process.execPath,
      args: ['--background']
    });
  } catch {
    startupError = 'unavailable';
  }
  return startupPublicState();
}

function startupPublicState() {
  const supported = isStartupSupported();
  let enabled = false;
  if (supported && !startupError) {
    try {
      enabled = Boolean(app.getLoginItemSettings({
        path: process.execPath,
        args: ['--background']
      }).openAtLogin);
    } catch {
      startupError = 'unavailable';
    }
  }
  return {
    supported,
    enabled: supported && !startupError ? enabled : false,
    requested: startupRequested,
    launchesInBackground: true,
    error: startupError
  };
}

function isStartupSupported() {
  return process.platform === 'win32' && app.isPackaged;
}

async function loadQuarantineKey() {
  const dataDirectory = app.getPath('userData');
  const protectedKeyFile = path.join(dataDirectory, 'quarantine-key.bin');
  await fs.mkdir(dataDirectory, { recursive: true });

  if (safeStorage.isEncryptionAvailable()) {
    try {
      const encrypted = await fs.readFile(protectedKeyFile);
      const value = safeStorage.decryptString(encrypted);
      assertQuarantineKey(value);
      return { value, developmentFallback: false };
    } catch (error) {
      if (error?.code !== 'ENOENT') throw operationError('QUARANTINE_KEY_INVALID', 'No se pudo desbloquear la clave de cuarentena.');
    }

    const value = crypto.randomBytes(32).toString('base64');
    const encrypted = safeStorage.encryptString(value);
    try {
      await fs.writeFile(protectedKeyFile, encrypted, { flag: 'wx', mode: 0o600 });
      return { value, developmentFallback: false };
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      const existing = safeStorage.decryptString(await fs.readFile(protectedKeyFile));
      assertQuarantineKey(existing);
      return { value: existing, developmentFallback: false };
    }
  }

  if (app.isPackaged) {
    throw operationError('SECURE_STORAGE_UNAVAILABLE', 'Windows no puede proteger la clave de cuarentena con DPAPI.');
  }

  const developmentKeyFile = path.join(dataDirectory, 'quarantine-key.development.bin');
  try {
    const existing = await fs.readFile(developmentKeyFile);
    if (existing.length !== 32) throw new Error('Invalid development key');
    return { value: existing.toString('base64'), developmentFallback: true };
  } catch (error) {
    if (error?.code !== 'ENOENT') throw operationError('QUARANTINE_KEY_INVALID', 'La clave de desarrollo no es válida.');
  }

  const key = crypto.randomBytes(32);
  try {
    await fs.writeFile(developmentKeyFile, key, { flag: 'wx', mode: 0o600 });
    return { value: key.toString('base64'), developmentFallback: true };
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const existing = await fs.readFile(developmentKeyFile);
    if (existing.length !== 32) throw operationError('QUARANTINE_KEY_INVALID', 'La clave de desarrollo no es válida.');
    return { value: existing.toString('base64'), developmentFallback: true };
  }
}

function assertQuarantineKey(value) {
  if (typeof value !== 'string' || value.length !== 44) throw new Error('Invalid quarantine key');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== value) throw new Error('Invalid quarantine key');
}

async function createMainWindow(applicationSession = session.fromPartition(APPLICATION_PARTITION)) {
  const initialBounds = getInitialWindowBounds();
  const window = new BrowserWindow({
    title: 'Aegis Guard',
    ...initialBounds,
    minWidth: 960,
    minHeight: 640,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: '#0b1220',
    webPreferences: {
      preload: PRELOAD_FILE,
      partition: APPLICATION_PARTITION,
      session: applicationSession,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      webviewTag: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      navigateOnDragDrop: false,
      spellcheck: false,
      safeDialogs: true,
      devTools: !app.isPackaged
    }
  });

  mainWindow = window;
  window.removeMenu();
  hardenWebContents(window);

  window.once('ready-to-show', () => {
    if (!window.isDestroyed() && !backgroundLaunch) window.show();
  });
  window.on('close', event => {
    if (isQuitting || shutdownStarted) return;
    if (!tray) { isQuitting = true; return; }
    event.preventDefault();
    window.hide();
  });
  window.on('closed', () => {
    if (mainWindow === window) mainWindow = null;
  });

  await window.loadURL(APPLICATION_ENTRY);
  return window;
}

function getInitialWindowBounds() {
  const fallback = { width: 1280, height: 820 };
  let workArea;
  try {
    const cursor = screen.getCursorScreenPoint();
    workArea = screen.getDisplayNearestPoint(cursor)?.workArea;
  } catch {
    return fallback;
  }
  if (
    !workArea
    || ![workArea.x, workArea.y, workArea.width, workArea.height].every(Number.isFinite)
    || workArea.width <= 0
    || workArea.height <= 0
  ) return fallback;

  // Around 80% width and 86% height keeps useful desktop context visible.
  // Caps prevent an oversized interface on 1440p, ultrawide and 4K displays.
  const width = adaptiveDimension(workArea.width, 960, 1720, 0.8);
  const height = adaptiveDimension(workArea.height, 640, 1120, 0.86);
  const x = width <= workArea.width ? workArea.x + Math.floor((workArea.width - width) / 2) : workArea.x;
  const y = height <= workArea.height ? workArea.y + Math.floor((workArea.height - height) / 2) : workArea.y;
  return { x, y, width, height };
}

function adaptiveDimension(available, minimum, maximum, ratio) {
  const target = Math.floor(available * ratio);
  return Math.max(minimum, Math.min(maximum, Math.floor(available), target));
}

function hardenWebContents(window) {
  const contents = window.webContents;
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));

  contents.on('will-navigate', (event, targetUrl) => {
    if (targetUrl !== APPLICATION_ENTRY) event.preventDefault();
  });
  contents.on('will-redirect', event => event.preventDefault());
  contents.on('will-attach-webview', event => event.preventDefault());
  contents.on('content-bounds-updated', event => event.preventDefault());
  contents.on('before-input-event', (event, input) => {
    const key = String(input.key).toLowerCase();
    const reload = key === 'f5' || ((input.control || input.meta) && key === 'r');
    const developerTools = key === 'f12' || ((input.control || input.meta) && input.shift && key === 'i');
    if (reload || (app.isPackaged && developerTools)) event.preventDefault();
  });
}

function hardenSession(applicationSession) {
  applicationSession.setPermissionCheckHandler(() => false);
  applicationSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));

  applicationSession.webRequest.onBeforeRequest((details, callback) => {
    callback({ cancel: !isApplicationUrl(details.url) });
  });

  applicationSession.webRequest.onHeadersReceived((details, callback) => {
    if (!isApplicationUrl(details.url)) {
      callback({ responseHeaders: details.responseHeaders });
      return;
    }
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [CONTENT_SECURITY_POLICY],
        'Cross-Origin-Opener-Policy': ['same-origin'],
        'Referrer-Policy': ['no-referrer'],
        'X-Content-Type-Options': ['nosniff']
      }
    });
  });

  applicationSession.on('will-download', event => event.preventDefault());
}

function registerLocalProtocol(applicationSession) {
  applicationSession.protocol.handle('aegis', async request => {
    try {
      if (!['GET', 'HEAD'].includes(request.method)) return response('Method not allowed', 405, 'text/plain; charset=utf-8');
      const url = new URL(request.url);
      if (url.protocol !== 'aegis:' || url.hostname !== 'app' || url.username || url.password || url.port) {
        return response('Not found', 404, 'text/plain; charset=utf-8');
      }

      const relativeFile = resolveProtocolPath(url);
      const file = resolveInside(RENDERER_DIRECTORY, relativeFile);
      const body = await fs.readFile(file);
      const headers = securityHeaders(contentTypeFor(file));
      return new Response(request.method === 'HEAD' ? null : body, { status: 200, headers });
    } catch {
      return response('Not found', 404, 'text/plain; charset=utf-8');
    }
  });
}

function resolveProtocolPath(url) {
  const decoded = decodeURIComponent(url.pathname);
  const relative = decoded === '/' || decoded === '' ? 'index.html' : decoded.slice(1);
  if (!relative || relative.includes('\\') || relative.includes('\0')) throw new Error('Invalid resource path');
  const segments = relative.split('/');
  if (segments.some(segment => !segment || segment === '.' || segment === '..' || segment.startsWith('.'))) {
    throw new Error('Invalid resource path');
  }
  return path.join(...segments);
}

function resolveInside(root, relative) {
  const candidate = path.resolve(root, relative);
  const relation = path.relative(path.resolve(root), candidate);
  if (!relation || relation.startsWith('..') || path.isAbsolute(relation)) throw new Error('Resource escapes renderer directory');
  return candidate;
}

function response(body, status, contentType) {
  return new Response(body, { status, headers: securityHeaders(contentType) });
}

function securityHeaders(contentType) {
  return {
    'Cache-Control': app.isPackaged ? 'public, max-age=3600' : 'no-store',
    'Content-Security-Policy': CONTENT_SECURITY_POLICY,
    'Content-Type': contentType,
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff'
  };
}

function contentTypeFor(file) {
  return ({
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.ico': 'image/x-icon',
    '.jpeg': 'image/jpeg',
    '.jpg': 'image/jpeg',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml; charset=utf-8',
    '.webp': 'image/webp',
    '.woff2': 'font/woff2'
  })[path.extname(file).toLowerCase()] ?? 'application/octet-stream';
}

function registerIpcHandlers() {
  registerHandler(IPC_CHANNELS.bootstrap, assertNoPayload, async () => {
    const bootstrap = await engine.request(WORKER_ACTIONS.bootstrap);
    return sanitizeBootstrap(bootstrap);
  });

  registerHandler(IPC_CHANNELS.chooseScanTarget, parseChooseTarget, request => chooseScanTarget(request.kind));

  registerHandler(IPC_CHANNELS.startScan, parseStartScan, async request => {
    if (activeScanContext) throw operationError('SCAN_BUSY', 'Ya hay un análisis en curso.');
    const context = request.mode === 'quick'
      ? quickTargetContext()
      : request.mode === 'full'
        ? fullTargetContext()
        : { ...await targetVault.consume(request.targetId), mode: 'deep' };
    activeScanContext = context;
    try {
      const report = await engine.request(
        WORKER_ACTIONS.startScan,
        {
          mode: request.mode,
          target: request.mode === 'full' ? undefined : request.mode === 'quick' ? 'quick' : context.path,
          autoQuarantine: request.autoQuarantine
        },
        { timeoutMs: 0 }
      );
      return sanitizeScanReport(report, context);
    } finally {
      activeScanContext = null;
    }
  });

  registerHandler(IPC_CHANNELS.cancelScan, assertNoPayload, () => engine.request(WORKER_ACTIONS.cancelScan));

  registerHandler(IPC_CHANNELS.listQuarantine, assertNoPayload, async () => {
    const inventory = await engine.request(WORKER_ACTIONS.listQuarantine);
    return sanitizeQuarantineInventory(inventory);
  });

  registerHandler(IPC_CHANNELS.quarantineIsolate, parseIsolateResult, async request => {
    activeMutationCount++;
    try {
      const metadata = await engine.request(WORKER_ACTIONS.isolateResult, request);
      return sanitizeQuarantineItem(metadata);
    } finally {
      activeMutationCount--;
    }
  });

  registerHandler(IPC_CHANNELS.restoreQuarantine, parseRestore, request => restoreQuarantine(request.id));
  registerHandler(IPC_CHANNELS.showQuarantinePath, parseQuarantinePath, request => showQuarantinePath(request.id));
  registerHandler(IPC_CHANNELS.exportReport, parseExportReport, request => exportLatestReport(request.format));
  registerHandler(IPC_CHANNELS.runNetworkAudit, assertNoPayload, async () => sanitizeNetworkReport(
    await engine.request(WORKER_ACTIONS.runNetworkAudit, undefined, { timeoutMs: 60_000 })
  ));
  registerHandler(IPC_CHANNELS.exportNetworkReport, parseExportReport, request => exportLatestNetworkReport(request.format));

  registerHandler(IPC_CHANNELS.startMonitor, parseMonitorStart, async request => {
    const context = await targetVault.consume(request.targetId);
    if (context.kind !== 'directory') throw operationError('DIRECTORY_REQUIRED', 'Selecciona una carpeta para la vigilancia.');
    const previous = activeMonitorContext;
    activeMonitorContext = context;
    try {
      const state = await engine.request(WORKER_ACTIONS.startMonitor, {
        target: context.path,
        autoQuarantine: request.autoQuarantine
      });
      return sanitizeMonitorState(state, context);
    } catch (error) {
      activeMonitorContext = previous;
      throw error;
    }
  });

  registerHandler(IPC_CHANNELS.stopMonitor, assertNoPayload, async () => {
    const state = await engine.request(WORKER_ACTIONS.stopMonitor);
    activeMonitorContext = null;
    return sanitizeMonitorState(state, null);
  });

  registerHandler(IPC_CHANNELS.pauseProtection, assertNoPayload, async () => {
    const state = await engine.request(WORKER_ACTIONS.pauseProtection);
    return sanitizeProtectionState(state);
  });

  registerHandler(IPC_CHANNELS.resumeProtection, assertNoPayload, async () => {
    const state = await engine.request(WORKER_ACTIONS.resumeProtection);
    return sanitizeProtectionState(state);
  });

  registerHandler(IPC_CHANNELS.saveSettings, parseSettings, async settings => {
    const saved = await engine.request(WORKER_ACTIONS.saveSettings, settings);
    const startup = applyLaunchAtStartup(saved.launchAtStartup !== false);
    const publicSettings = sanitizeSettings(saved);
    scheduledSettings = publicSettings;
    return { ...publicSettings, settings: publicSettings, startup };
  });

  registerHandler(IPC_CHANNELS.createAndScanSimulation, assertNoPayload, async () => {
    if (activeScanContext) throw operationError('SCAN_BUSY', 'Ya hay un análisis en curso.');
    const context = simulationTargetContext();
    activeScanContext = context;
    try {
      const report = await engine.request(WORKER_ACTIONS.createAndScanSimulation, undefined, { timeoutMs: 0 });
      return sanitizeScanReport(report, context);
    } finally {
      activeScanContext = null;
    }
  });

  registerHandler(IPC_CHANNELS.checkForUpdates, assertNoPayload, () => updateService.check());

  registerHandler(IPC_CHANNELS.installUpdate, assertNoPayload, async () => {
    if (!updateService.canInstall()) throw operationError('UPDATE_NOT_READY', 'La actualización aún no está preparada.');
    if (activeMonitorContext) {
      await engine.request(WORKER_ACTIONS.stopMonitor);
      activeMonitorContext = null;
    }
    shutdownStarted = true;
    isQuitting = true;
    await gracefulShutdown();
    updateService.installNow();
    return { status: 'restarting' };
  });
}

function registerHandler(channel, parse, handler) {
  ipcMain.handle(channel, async (event, rawPayload) => {
    assertTrustedSender(event);
    try {
      const payload = parse(rawPayload);
      return await handler(payload);
    } catch (error) {
      throw toPublicError(error);
    }
  });
}

function assertTrustedSender(event) {
  if (!mainWindow || mainWindow.isDestroyed() || event.sender !== mainWindow.webContents) {
    throw new ContractError('Untrusted IPC sender', 'UNTRUSTED_SENDER');
  }
  if (!event.senderFrame || event.senderFrame !== event.sender.mainFrame || !isApplicationUrl(event.senderFrame.url)) {
    throw new ContractError('Untrusted IPC frame', 'UNTRUSTED_SENDER');
  }
}

async function chooseScanTarget(requestedKind) {
  let kind = requestedKind;
  if (!kind) {
    const typeChoice = await dialog.showMessageBox(mainWindow, {
      type: 'question',
      title: 'Seleccionar objetivo',
      message: '¿Qué quieres analizar?',
      detail: 'Aegis solo tendrá acceso al archivo o carpeta que selecciones.',
      buttons: ['Carpeta', 'Archivo', 'Cancelar'],
      defaultId: 0,
      cancelId: 2,
      noLink: true
    });
    if (typeChoice.response === 2) return null;
    kind = typeChoice.response === 0 ? 'directory' : 'file';
  }
  const selected = await dialog.showOpenDialog(mainWindow, {
    title: kind === 'directory' ? 'Selecciona una carpeta' : 'Selecciona un archivo',
    buttonLabel: 'Seleccionar',
    properties: [kind === 'directory' ? 'openDirectory' : 'openFile', 'dontAddToRecent']
  });
  if (selected.canceled || selected.filePaths.length !== 1) return null;

  const target = await targetVault.add(selected.filePaths[0], kind);
  return { targetId: target.id, label: target.label, kind: target.kind };
}

async function restoreQuarantine(id) {
  const inventory = await engine.request(WORKER_ACTIONS.listQuarantine);
  const items = Array.isArray(inventory) ? inventory : Array.isArray(inventory?.items) ? inventory.items : [];
  const metadata = items.find(item => item?.id === id);
  if (!metadata) throw operationError('QUARANTINE_NOT_FOUND', 'El elemento ya no está en cuarentena.');

  if (typeof metadata.originalPath !== 'string' || !path.isAbsolute(metadata.originalPath)) {
    throw operationError('INVALID_ORIGINAL_PATH', 'La cuarentena no conserva una ruta original válida.');
  }
  const destination = path.resolve(metadata.originalPath);
  activeMutationCount++;
  let result;
  try { result = await engine.request(WORKER_ACTIONS.restoreQuarantine, { id, destination }); }
  finally { activeMutationCount--; }
  const label = safeLabel(path.basename(String(result ?? destination)));
  return { cancelled: false, restored: true, id, name: label, label };
}

async function showQuarantinePath(id) {
  const inventory = await engine.request(WORKER_ACTIONS.listQuarantine);
  const items = Array.isArray(inventory) ? inventory : Array.isArray(inventory?.items) ? inventory.items : [];
  const metadata = items.find(item => item?.id === id);
  if (!metadata || typeof metadata.originalPath !== 'string' || !path.isAbsolute(metadata.originalPath)) {
    throw operationError('QUARANTINE_NOT_FOUND', 'No se conserva una ruta original válida para este elemento.');
  }
  const originalPath = path.resolve(metadata.originalPath);
  await dialog.showMessageBox(mainWindow, {
    type: 'info', title: 'Ruta original', message: path.basename(originalPath), detail: originalPath,
    buttons: ['Cerrar'], defaultId: 0, cancelId: 0, noLink: true
  });
  return { shown: true };
}

async function exportLatestReport(format) {
  const report = await engine.request(WORKER_ACTIONS.getLatestReport, { format });
  const reportsRoot = path.resolve(app.getPath('userData'), 'reports');
  const source = path.resolve(String(report?.path ?? ''));
  const relative = path.relative(reportsRoot, source);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw operationError('INVALID_REPORT_PATH', 'La ruta interna del informe no es válida.');
  }
  const date = String(report.completedAt ?? new Date().toISOString()).slice(0, 10);
  const selected = await dialog.showSaveDialog(mainWindow, {
    title: 'Descargar informe completo',
    defaultPath: path.join(app.getPath('downloads'), `Aegis-Guard-informe-${date}.${format}`),
    buttonLabel: 'Guardar informe',
    filters: [{ name: format === 'json' ? 'Informe JSON' : 'Informe CSV', extensions: [format] }],
    properties: ['showOverwriteConfirmation', 'dontAddToRecent']
  });
  if (selected.canceled || !selected.filePath) return { cancelled: true };
  const destination = path.resolve(selected.filePath);
  await fs.copyFile(source, destination);
  return { cancelled: false, format, count: safeCount(report.count), label: safeLabel(path.basename(destination)) };
}

async function exportLatestNetworkReport(format) {
  const report = await engine.request(WORKER_ACTIONS.getLatestNetworkReport, { format });
  const reportsRoot = path.resolve(app.getPath('userData'), 'reports');
  const source = path.resolve(String(report?.path ?? ''));
  const relative = path.relative(reportsRoot, source);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw operationError('INVALID_REPORT_PATH', 'La ruta interna del informe de red no es válida.');
  const date = String(report.completedAt ?? new Date().toISOString()).slice(0, 10);
  const selected = await dialog.showSaveDialog(mainWindow, { title:'Descargar auditoría de red', defaultPath:path.join(app.getPath('downloads'),`Aegis-Guard-red-${date}.${format}`), buttonLabel:'Guardar informe', filters:[{name:format==='json'?'Informe JSON':'Informe CSV',extensions:[format]}], properties:['showOverwriteConfirmation','dontAddToRecent'] });
  if (selected.canceled || !selected.filePath) return { cancelled:true };
  await fs.copyFile(source, path.resolve(selected.filePath));
  return { cancelled:false, format, count:safeCount(report.count), label:safeLabel(path.basename(selected.filePath)) };
}

function publishEvent(event) {
  if (!event || !mainWindow || mainWindow.isDestroyed() || mainWindow.webContents.isDestroyed()) return;
  mainWindow.webContents.send(EVENT_CHANNEL, event);
}

function sanitizeWorkerEvent(event) {
  if (!event || typeof event !== 'object' || typeof event.type !== 'string') return null;
  const payload = event.payload && typeof event.payload === 'object' ? event.payload : {};
  switch (event.type) {
    case 'scan-started':
      return {
        type: event.type,
        payload: {
          scanId: safeUuid(payload.scanId),
          mode: safeScanMode(activeScanContext?.mode ?? payload.mode),
          target: publicTarget(activeScanContext),
          targetLabel: publicTarget(activeScanContext)?.label ?? '',
          label: publicTarget(activeScanContext)?.label ?? '',
          startedAt: safeDate(payload.startedAt),
          autoQuarantine: Boolean(payload.autoQuarantine),
          rootsTotal: payload.rootsTotal == null ? payload.rootsTotal : safeCount(payload.rootsTotal)
        }
      };
    case 'scan-progress':
      return {
        type: event.type,
        payload: {
          scanId: safeUuid(payload.scanId),
          mode: safeScanMode(activeScanContext?.mode ?? payload.mode),
          phase: ['discovering', 'scanning'].includes(payload.phase) ? payload.phase : 'scanning',
          discovered: safeCount(payload.filesDiscovered ?? payload.discovered),
          filesDiscovered: safeCount(payload.filesDiscovered ?? payload.discovered),
          total: payload.total === null ? null : safeCount(payload.total),
          completed: safeCount(payload.completed),
          bytesDiscovered: safeCount(payload.bytesDiscovered),
          bytesCompleted: safeCount(payload.bytesCompleted),
          malicious: safeCount(payload.malicious),
          suspicious: safeCount(payload.suspicious),
          threats: safeCount(payload.threats),
          errors: safeCount(payload.errors),
          fileErrors: safeCount(payload.fileErrors),
          skipped: safeCount(payload.skipped),
          traversalErrors: safeCount(payload.traversalErrors),
          traversalSkipped: safeCount(payload.traversalSkipped),
          linksSkipped: safeCount(payload.linksSkipped),
          currentPath: presentPath(payload.currentPath, activeScanContext),
          currentFile: presentPath(payload.currentPath, activeScanContext),
          targetLabel: publicTarget(activeScanContext)?.label ?? '',
          rootsTotal: payload.rootsTotal == null ? payload.rootsTotal : safeCount(payload.rootsTotal),
          rootsCompleted: payload.rootsCompleted === undefined ? undefined : safeCount(payload.rootsCompleted),
          currentRootLabel: rootDisplayLabel(payload.currentRoot),
          result: payload.result ? {
            ...sanitizeScanResult(payload.result, activeScanContext),
            scanId: safeUuid(payload.scanId)
          } : undefined
        }
      };
    case 'scan-detection':
      return {
        type: event.type,
        payload: {
          scanId: safeUuid(payload.scanId),
          mode: safeScanMode(activeScanContext?.mode ?? payload.mode),
          result: { ...sanitizeScanResult(payload.result, activeScanContext), scanId: safeUuid(payload.scanId) }
        }
      };
    case 'scan-completed':
      return { type: event.type, payload: sanitizeScanReport(payload, activeScanContext) };
    case 'scan-cancelled':
      return { type: event.type, payload: sanitizeScanReport(payload, activeScanContext) };
    case 'scan-error':
      return {
        type: event.type,
        payload: {
          scanId: safeUuid(payload.scanId),
          mode: safeScanMode(activeScanContext?.mode ?? payload.mode),
          target: publicTarget(activeScanContext),
          message: 'El análisis no pudo completarse.'
        }
      };
    case 'scan-warning':
      return {
        type: event.type,
        payload: {
          scanId: safeUuid(payload.scanId),
          mode: safeScanMode(activeScanContext?.mode ?? payload.mode),
          code: payload.code === 'STATE_NOT_PERSISTED' ? payload.code : 'SCAN_WARNING',
          message: 'El análisis terminó, pero su historial no pudo guardarse.'
        }
      };
    case 'scan-traversal-error':
      return {
        type: event.type,
        payload: {
          scanId: safeUuid(payload.scanId),
          mode: safeScanMode(activeScanContext?.mode ?? payload.mode),
          currentRootLabel: rootDisplayLabel(payload.currentRoot),
          message: 'No se pudo acceder a una ubicación.'
        }
      };
    case 'scan-traversal-skipped':
      return {
        type: event.type,
        payload: {
          scanId: safeUuid(payload.scanId),
          mode: safeScanMode(activeScanContext?.mode ?? payload.mode),
          currentRootLabel: rootDisplayLabel(payload.currentRoot),
          reason: ['link', 'outside-root', 'duplicate', 'internal-transient'].includes(payload.reason)
            ? payload.reason
            : 'safety',
          message: payload.reason === 'internal-transient'
            ? 'Se omitió un archivo temporal interno de Aegis.'
            : 'Se omitió un enlace o punto de reanálisis por seguridad.'
        }
      };
    case 'monitor-changed':
      return {
        type: payload.active ? 'monitor-started' : 'monitor-stopped',
        payload: sanitizeMonitorState(payload, activeMonitorContext)
      };
    case 'monitor-result': {
      const result = sanitizeScanResult(payload.result, activeMonitorContext);
      return result.verdict === 'clean' ? null : { type: 'monitor-detection', payload: { result } };
    }
    case 'monitor-error':
      return { type: event.type, payload: { message: 'La vigilancia de la carpeta se ha detenido por un error.' } };
    case 'protection-state-changed':
      return { type: event.type, payload: sanitizeProtectionState(payload) };
    case 'protection-detection':
      return {
        type: event.type,
        payload: { result: sanitizeScanResult(payload.result, downloadsProtectionContext()) }
      };
    case 'protection-error':
      return { type: event.type, payload: { message: 'La protección de Descargas no está disponible.' } };
    case 'protection-warning':
      return { type: event.type, payload: { message: 'La cola de protección está llena; recomendamos analizar Descargas.' } };
    case 'quarantine-changed':
      {
        const item = payload.item ? sanitizeQuarantineItem(payload.item) : null;
      return {
        type: event.type,
        payload: {
          action: safeLabel(payload.action),
          id: safeUuid(payload.id ?? item?.id),
          resultId: safeUuid(payload.resultId),
          name: item?.name ?? safeLabel(path.basename(String(payload.path ?? 'archivo'))),
          item
        }
      };
      }
    case 'settings-changed':
      return { type: event.type, payload: sanitizeSettings(payload) };
    default:
      return null;
  }
}

function sanitizeBootstrap(value) {
  const input = value && typeof value === 'object' ? value : {};
  const lastSummary = input.lastSummary ? sanitizeSummary(input.lastSummary) : null;
  const lastScanAt = safeDate(input.lastScanAt);
  const quarantine = Array.isArray(input.quarantine) ? input.quarantine.map(sanitizeQuarantineItem) : [];
  const quarantineInventory = sanitizeQuarantineInventory({
    items: quarantine,
    total: input.quarantineInventory?.total ?? input.quarantineCount ?? quarantine.length,
    truncatedCount: input.quarantineInventory?.truncatedCount,
    corruptCount: input.quarantineInventory?.corruptCount,
    oversizedCount: input.quarantineInventory?.oversizedCount
  }, { itemsAlreadySanitized: true });
  return {
    version: safeLabel(input.version ?? app.getVersion()),
    engineVersion: safeLabel(input.version ?? app.getVersion()),
    definitions: {
      version: safeLabel(input.definitions?.version),
      generatedAt: safeDate(input.definitions?.generatedAt)
    },
    definitionsVersion: safeLabel(input.definitions?.version),
    settings: sanitizeSettings(input.settings),
    startup: startupPublicState(),
    lastScanAt,
    lastSummary,
    lastScan: lastSummary ? { completedAt: lastScanAt, summary: lastSummary } : null,
    totalScanned: lastSummary?.scanned ?? 0,
    reportAvailable: Boolean(input.reportAvailable),
    network: input.network ? sanitizeNetworkReport(input.network) : null,
    health: sanitizeHealth(input.health),
    activity: Array.isArray(input.activity) ? input.activity.slice(0, 100).map(sanitizeActivity) : [],
    quarantine,
    quarantineCount: quarantineInventory.total,
    quarantineInventory: {
      total: quarantineInventory.total,
      truncatedCount: quarantineInventory.truncatedCount,
      corruptCount: quarantineInventory.corruptCount,
      oversizedCount: quarantineInventory.oversizedCount,
      hasMore: quarantineInventory.hasMore
    },
    monitor: sanitizeMonitorState(input.monitor, activeMonitorContext),
    protection: sanitizeProtectionState(input.protection),
    updates: {
      ...(updateService?.publicState() ?? { status: 'unavailable' }),
      supported: updateService?.status !== 'unavailable',
      channel: 'stable'
    }
  };
}

function sanitizeHealth(value) {
  const input = value && typeof value === 'object' ? value : {};
  return {
    status: input.status === 'healthy' ? 'healthy' : 'degraded',
    authenticatedWorkerIpc: Boolean(input.authenticatedWorkerIpc),
    protectionAvailable: Boolean(input.protectionAvailable),
    statePersistenceAvailable: Boolean(input.statePersistenceAvailable),
    recoveredInterruptedOperation: Boolean(input.recoveredInterruptedOperation)
  };
}

function sanitizeNetworkReport(value) {
  const input = value && typeof value === 'object' ? value : {};
  const events = Array.isArray(input.events) ? input.events.slice(0, 500).map(item => ({
    verdict: item?.verdict === 'suspicious' ? 'suspicious' : 'observed',
    explanation: safeText(item?.explanation, 500), protocol: safeLabel(item?.protocol),
    remoteAddress: safeText(item?.remoteAddress, 128), remotePort: safeCount(item?.remotePort), domain: safeText(item?.domain, 253),
    process: { id:safeCount(item?.process?.id), name:safeText(item?.process?.name,260), path:safeText(item?.process?.path,1000) },
    signature: { status:item?.signature?.status==='valid'?'valid':'unverified', publisher:safeText(item?.signature?.publisher,300) }
  })) : [];
  return { completedAt:safeDate(input.completedAt), reportAvailable:Boolean(input.reportAvailable), summary:{connections:safeCount(input.summary?.connections),suspicious:safeCount(input.summary?.suspicious),unsignedProcesses:safeCount(input.summary?.unsignedProcesses),truncated:Boolean(input.summary?.truncated)}, windowsSecurity:{firewall:Array.isArray(input.windowsSecurity?.firewall)?input.windowsSecurity.firewall.slice(0,8).map(x=>({name:safeLabel(x?.name),enabled:Boolean(x?.enabled),defaultInboundAction:safeLabel(x?.defaultInboundAction),defaultOutboundAction:safeLabel(x?.defaultOutboundAction)})):[],defender:input.windowsSecurity?.defender?{antivirusEnabled:Boolean(input.windowsSecurity.defender.antivirusEnabled),realTimeProtectionEnabled:Boolean(input.windowsSecurity.defender.realTimeProtectionEnabled),networkInspectionEnabled:Boolean(input.windowsSecurity.defender.networkInspectionEnabled)}:null}, events };
}

function sanitizeScanReport(value, context) {
  const input = value && typeof value === 'object' ? value : {};
  const scanId = safeUuid(input.scanId);
  return {
    scanId,
    mode: safeScanMode(context?.mode ?? input.mode),
    target: publicTarget(context),
    path: publicTarget(context)?.label ?? '',
    cancelled: Boolean(input.cancelled),
    completedAt: safeDate(input.completedAt),
    summary: sanitizeSummary(input.summary),
    results: Array.isArray(input.results)
      ? input.results.map(item => ({ ...sanitizeScanResult(item, context), scanId }))
      : [],
    resultsTruncated: safeCount(input.resultsTruncated),
    reportAvailable: Boolean(input.reportAvailable)
  };
}

function sanitizeScanResult(value, context) {
  const input = value && typeof value === 'object' ? value : {};
  const displayPath = presentPath(input.path, context);
  return {
    resultId: safeUuid(input.resultId),
    path: displayPath,
    displayPath,
    size: safeCount(input.size),
    sha256: typeof input.sha256 === 'string' && /^[0-9a-f]{64}$/i.test(input.sha256) ? input.sha256.toLowerCase() : null,
    score: safeScore(input.score),
    verdict: ['clean', 'suspicious', 'malicious', 'skipped', 'error'].includes(input.verdict) ? input.verdict : 'error',
    classification: input.classification === 'pua' ? 'pua' : 'malware',
    findings: Array.isArray(input.findings) ? input.findings.slice(0, 100).map(finding => ({
      id: safeLabel(finding?.id),
      description: safeText(finding?.description, 500),
      score: safeScore(finding?.score)
    })) : [],
    durationMs: safeCount(input.durationMs),
    error: input.error ? 'No se pudo leer este archivo.' : undefined,
    action: ['quarantined', 'quarantine-error'].includes(input.action) ? input.action : undefined,
    quarantineId: input.quarantineId ? safeUuid(input.quarantineId) : undefined,
    trust: input.trust && typeof input.trust === 'object' ? {
      status: safeLabel(input.trust.status),
      subject: safeText(input.trust.subject, 500),
      organization: safeText(input.trust.organization, 200),
      isOsBinary: Boolean(input.trust.isOsBinary),
      signatureType: safeLabel(input.trust.signatureType),
      thumbprint: safeText(input.trust.thumbprint, 100),
      notBefore: safeDate(input.trust.notBefore),
      notAfter: safeDate(input.trust.notAfter),
      chainValid: Boolean(input.trust.chainValid),
      chainStatus: Array.isArray(input.trust.chainStatus) ? input.trust.chainStatus.slice(0, 16).map(value => safeLabel(value)) : [],
      timestamped: Boolean(input.trust.timestamped),
      timestampSubject: safeText(input.trust.timestampSubject, 500),
      trustedPublisher: Boolean(input.trust.trustedPublisher),
      applicationVerified: Boolean(input.trust.applicationVerified),
      companyName: safeText(input.trust.companyName, 200),
      productName: safeText(input.trust.productName, 200),
      fileVersion: safeText(input.trust.fileVersion, 100),
      zoneId: Number.isSafeInteger(input.trust.zoneId) ? input.trust.zoneId : null,
      origin: ['windows', 'program-files', 'program-files-x86', 'installed-user-application', 'other'].includes(input.trust.origin) ? input.trust.origin : 'other'
    } : undefined
  };
}

function sanitizeSummary(value) {
  const input = value && typeof value === 'object' ? value : {};
  return {
    scanned: safeCount(input.scanned),
    malicious: safeCount(input.malicious),
    suspicious: safeCount(input.suspicious),
    errors: safeCount(input.errors),
    skipped: safeCount(input.skipped),
    quarantined: safeCount(input.quarantined),
    traversalErrors: safeCount(input.traversalErrors),
    traversalSkipped: safeCount(input.traversalSkipped),
    linksSkipped: safeCount(input.linksSkipped),
    rootsScanned: safeCount(input.rootsScanned),
    durationMs: safeCount(input.durationMs)
  };
}

function sanitizeQuarantineItem(value) {
  const input = value && typeof value === 'object' ? value : {};
  const originalPath = String(input.originalPath ?? 'archivo');
  const displayPath = compactPath(originalPath);
  return {
    id: safeUuid(input.id),
    name: safeLabel(path.basename(originalPath) || 'archivo'),
    originalPath: displayPath,
    displayPath,
    quarantinedAt: safeDate(input.quarantinedAt),
    sha256: typeof input.sha256 === 'string' && /^[0-9a-f]{64}$/i.test(input.sha256) ? input.sha256.toLowerCase() : null,
    verdict: ['suspicious', 'malicious'].includes(input.verdict) ? input.verdict : 'malicious',
    score: safeScore(input.score),
    findings: Array.isArray(input.findings) ? input.findings.slice(0, 100).map(finding => ({
      id: safeLabel(finding?.id),
      description: safeText(finding?.description, 500),
      score: safeScore(finding?.score)
    })) : []
  };
}

function sanitizeQuarantineInventory(value, { itemsAlreadySanitized = false } = {}) {
  const input = value && typeof value === 'object' ? value : {};
  const sourceItems = Array.isArray(input) ? input : Array.isArray(input.items) ? input.items : [];
  const items = itemsAlreadySanitized ? sourceItems.slice(0, 5_000) : sourceItems.slice(0, 5_000).map(sanitizeQuarantineItem);
  const total = Math.max(items.length, safeCount(input.total ?? sourceItems.length));
  const truncatedCount = Math.max(safeCount(input.truncatedCount), total - items.length);
  const corruptCount = safeCount(input.corruptCount);
  const oversizedCount = safeCount(input.oversizedCount);
  return {
    items,
    total,
    truncatedCount,
    corruptCount,
    oversizedCount,
    hasMore: truncatedCount > 0
  };
}

function sanitizeSettings(value) {
  const input = value && typeof value === 'object' ? value : {};
  return {
    theme: ['system', 'light', 'dark'].includes(input.theme) ? input.theme : 'system',
    autoQuarantine: Boolean(input.autoQuarantine),
    notifications: input.notifications !== false,
    checkUpdates: input.checkUpdates !== false,
    updateChannel: ['stable', 'beta'].includes(input.updateChannel) ? input.updateChannel : 'stable',
    launchAtStartup: input.launchAtStartup !== false,
    scheduledScanEnabled: Boolean(input.scheduledScanEnabled),
    scheduledScanMode: input.scheduledScanMode === 'full' ? 'full' : 'quick',
    scheduledScanHour: Number.isSafeInteger(input.scheduledScanHour) && input.scheduledScanHour >= 0 && input.scheduledScanHour <= 23 ? input.scheduledScanHour : 3,
    skipScheduledScanOnBattery: input.skipScheduledScanOnBattery !== false
  };
}

function sanitizeActivity(value) {
  const input = value && typeof value === 'object' ? value : {};
  const type = safeLabel(input.type);
  const summary = input.summary ? sanitizeSummary(input.summary) : undefined;
  const displayPath = compactPath(input.path);
  return {
    type,
    kind: type === 'restore' ? 'quarantine' : type.startsWith('monitor') || type.startsWith('protection') ? 'monitor' : 'scan',
    title: type === 'restore' ? 'Archivo restaurado' : type.startsWith('monitor') || type.startsWith('protection') ? 'Detección de vigilancia' : 'Análisis completado',
    description: summary
      ? `${summary.scanned} archivos · ${summary.malicious + summary.suspicious} indicios`
      : displayPath || 'Actividad de Aegis',
    at: safeDate(input.at),
    path: displayPath,
    verdict: ['clean', 'suspicious', 'malicious', 'skipped', 'error'].includes(input.verdict) ? input.verdict : undefined,
    score: input.score === undefined ? undefined : safeScore(input.score),
    summary
  };
}

function sanitizeMonitorState(value, context) {
  const input = value && typeof value === 'object' ? value : {};
  const active = Boolean(input.active);
  const hasTarget = active || Boolean(input.pending);
  return {
    active,
    paused: Boolean(input.paused),
    pending: Boolean(input.pending),
    target: hasTarget ? publicTarget(context) : null,
    path: hasTarget ? publicTarget(context)?.label ?? '' : '',
    autoQuarantine: Boolean(input.autoQuarantine)
  };
}

function sanitizeProtectionState(value) {
  const input = value && typeof value === 'object' ? value : {};
  return {
    active: Boolean(input.active),
    paused: Boolean(input.paused),
    targetLabel: 'Descargas',
    autoQuarantine: Boolean(input.autoQuarantine),
    sessionOnly: true,
    error: input.error ? 'unavailable' : null
  };
}

function presentPath(value, context) {
  if (typeof value !== 'string' || value.length === 0) return '';
  if (!path.isAbsolute(value)) return safeText(value, 500);
  if (!context?.path) return compactPath(value);

  const candidate = path.resolve(value);
  const root = path.resolve(context.path);
  if (context.kind === 'file') return context.label;
  const relative = path.relative(root, candidate);
  if (!relative) return context.label;
  if (relative.startsWith('..') || path.isAbsolute(relative)) return compactPath(candidate);
  return safeText(path.join(context.label, relative), 500);
}

function compactPath(value) {
  if (typeof value !== 'string' || value.length === 0) return '';
  const normalized = path.normalize(value);
  const parts = normalized.split(/[\\/]+/).filter(Boolean);
  return safeText(parts.slice(-2).join(path.sep) || path.basename(normalized) || 'archivo', 500);
}

function publicTarget(context) {
  if (!context) return null;
  return {
    id: context.id ?? null,
    targetId: context.id ?? null,
    label: context.label,
    kind: context.kind,
    mode: context.mode
  };
}

function quickTargetContext() {
  return {
    id: null,
    path: app.getPath('downloads'),
    label: 'Descargas',
    kind: 'directory',
    mode: 'quick'
  };
}

function fullTargetContext() {
  return { id: null, path: null, label: 'Este equipo', kind: 'computer', mode: 'full' };
}

function downloadsProtectionContext() {
  return { id: null, path: app.getPath('downloads'), label: 'Descargas', kind: 'directory', mode: 'protection' };
}

function simulationTargetContext() {
  return { id: null, path: null, label: 'Simulación segura', kind: 'file', mode: 'simulation' };
}

function safeCount(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.min(Math.trunc(number), Number.MAX_SAFE_INTEGER) : 0;
}

function safeScore(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
}

function safeScanMode(value) {
  if (value === 'custom') return 'deep';
  return ['quick', 'deep', 'full', 'simulation'].includes(value) ? value : 'deep';
}

function rootDisplayLabel(value) {
  if (typeof value !== 'string' || value.length === 0) return '';
  const match = path.parse(value).root.match(/^([A-Za-z]):/);
  return match ? `Unidad ${match[1].toUpperCase()}` : 'Unidad local';
}

function safeDate(value) {
  if (value === null || value === undefined || value === '') return null;
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? null : date.toISOString();
}

function safeUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
    ? value.toLowerCase()
    : null;
}

function safeLabel(value) {
  return safeText(value, 240);
}

function safeText(value, maximum) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maximum);
}

function isApplicationUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'aegis:' && url.hostname === 'app' && !url.username && !url.password && !url.port;
  } catch {
    return false;
  }
}

function toPublicError(error) {
  if (error instanceof ContractError) return error;
  const messages = {
    ALREADY_INITIALIZED: 'El servicio ya estaba iniciado.',
    DIRECTORY_REQUIRED: 'Selecciona una carpeta para esta operación.',
    DRIVE_ENUMERATION_FAILED: 'Windows no pudo enumerar las unidades locales de forma segura.',
    NOT_INITIALIZED: 'El servicio de análisis no está disponible.',
    QUARANTINE_NOT_FOUND: 'El elemento ya no está en cuarentena.',
    QUARANTINE_KEY_INVALID: 'No se pudo desbloquear la clave de cuarentena.',
    SCAN_BUSY: 'Ya hay un análisis en curso.',
    SECURE_STORAGE_UNAVAILABLE: 'Windows no puede proteger la clave de cuarentena.',
    TARGET_CHANGED: 'El objetivo seleccionado ha cambiado.',
    TARGET_EXPIRED: 'Vuelve a seleccionar el objetivo.',
    UPDATE_NOT_READY: 'La actualización aún no está preparada.',
    WORKER_EXITED: 'El servicio de análisis se ha detenido.',
    WORKER_TIMEOUT: 'El servicio de análisis no respondió a tiempo.'
  };
  return operationError(error?.code ?? 'OPERATION_FAILED', messages[error?.code] ?? 'La operación no pudo completarse.');
}

function operationError(code, message) {
  const error = new Error(message);
  error.name = 'AegisError';
  error.code = code;
  return error;
}

class EngineBridge {
  constructor(onEvent) {
    this.onEvent = onEvent;
    this.child = null;
    this.pending = new Map();
    this.ready = null;
    this.readyResolve = null;
    this.readyReject = null;
    this.disposed = false;
    this.authKey = crypto.randomBytes(32).toString('base64');
  }

  async start(options) {
    if (this.child) throw operationError('ALREADY_INITIALIZED', 'The scan worker has already started');
    this.ready = new Promise((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    const readinessTimeout = setTimeout(() => {
      this.readyReject?.(operationError('WORKER_TIMEOUT', 'The scan worker did not become ready'));
    }, 15_000);
    this.ready.finally(() => clearTimeout(readinessTimeout)).catch(() => {});

    this.child = utilityProcess.fork(WORKER_FILE, [], {
      serviceName: 'Aegis Guard Scan Engine',
      env: { ...process.env, AEGIS_WORKER_AUTH_KEY: this.authKey }
    });
    this.child.on('message', message => this.handleMessage(message?.data ?? message));
    this.child.on('exit', code => this.handleExit(code));
    this.child.on('error', error => this.handleFailure(error));

    await this.ready;
    return this.request(WORKER_ACTIONS.initialize, options, { timeoutMs: 30_000, skipReady: true });
  }

  async request(action, payload, { timeoutMs = 30_000, skipReady = false } = {}) {
    if (this.disposed) throw operationError('WORKER_EXITED', 'The scan worker is not running');
    if (!skipReady) await this.ready;
    if (!this.child) throw operationError('WORKER_EXITED', 'The scan worker is not running');

    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      let timeout = null;
      if (timeoutMs > 0) {
        timeout = setTimeout(() => {
          this.pending.delete(id);
          reject(operationError('WORKER_TIMEOUT', 'The scan worker did not respond in time'));
        }, timeoutMs);
      }
      this.pending.set(id, { resolve, reject, timeout });
      try {
        this.child.postMessage(signWorkerMessage({ kind: 'request', id, action, payload }, this.authKey));
      } catch (error) {
        if (timeout) clearTimeout(timeout);
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  handleMessage(message) {
    message = verifyWorkerMessage(message, this.authKey);
    if (!message) {
      this.handleFailure(operationError('WORKER_AUTH_FAILED', 'The scan worker sent an unauthenticated message'));
      return;
    }
    if (message.kind === 'ready') {
      if (message.protocolVersion !== WORKER_PROTOCOL_VERSION) {
        this.readyReject?.(operationError('WORKER_PROTOCOL', 'Incompatible scan worker protocol'));
      } else {
        this.readyResolve?.();
      }
      return;
    }
    if (message.kind === 'event') {
      this.onEvent(message.event);
      return;
    }
    if (message.kind !== 'response' || typeof message.id !== 'string') return;
    const request = this.pending.get(message.id);
    if (!request) return;
    this.pending.delete(message.id);
    if (request.timeout) clearTimeout(request.timeout);
    if (message.ok) {
      request.resolve(message.result);
      return;
    }
    const error = operationError(message.error?.code ?? 'OPERATION_FAILED', message.error?.message ?? 'Scan operation failed');
    request.reject(error);
  }

  handleFailure(error) {
    this.readyReject?.(error);
    this.rejectAll(error);
  }

  handleExit(code) {
    const error = operationError('WORKER_EXITED', `The scan worker exited with code ${code}`);
    this.readyReject?.(error);
    this.rejectAll(error);
    this.child = null;
    if (!this.disposed && !isQuitting) this.onEvent({ type: 'service-error', payload: { message: 'El servicio de análisis se ha detenido.' } });
  }

  rejectAll(error) {
    for (const request of this.pending.values()) {
      if (request.timeout) clearTimeout(request.timeout);
      request.reject(error);
    }
    this.pending.clear();
  }

  async shutdown() {
    if (this.disposed || !this.child) return;
    await this.request(WORKER_ACTIONS.shutdown, undefined, { timeoutMs: 15_000 });
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.rejectAll(operationError('WORKER_EXITED', 'The application is closing'));
    try { this.child?.kill(); } catch { /* process is already gone */ }
    this.child = null;
  }
}
