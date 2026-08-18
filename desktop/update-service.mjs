export class UpdateService {
  constructor({ app, publish = () => {}, isBusy = () => false }) {
    this.app = app;
    this.publish = publish;
    this.isBusy = isBusy;
    this.status = app.isPackaged ? 'initializing' : 'unavailable';
    this.downloaded = false;
  }

  async initialize() {
    if (!this.app.isPackaged) {
      this.status = 'unavailable';
      return this.publicState('Las actualizaciones firmadas solo están disponibles en la versión instalada.');
    }
    try {
      const module = await import('electron-updater');
      this.updater = module.autoUpdater ?? module.default?.autoUpdater;
      if (!this.updater) throw new Error('Updater export not found');
    } catch {
      this.status = 'unavailable';
      return this.publicState('El componente de actualización no está incluido en esta compilación.');
    }

    this.updater.allowPrerelease = false;
    this.updater.allowDowngrade = false;
    this.updater.disableWebInstaller = true;
    this.updater.autoDownload = true;
    this.updater.autoInstallOnAppQuit = false;
    this.bindEvents();
    this.status = 'idle';
    return this.publicState();
  }

  bindEvents() {
    this.updater.on('checking-for-update', () => this.setStatus('checking'));
    this.updater.on('update-available', info => {
      this.version = safeVersion(info?.version);
      this.setStatus('available', { version: this.version });
    });
    this.updater.on('update-not-available', info => {
      this.version = safeVersion(info?.version ?? this.app.getVersion());
      this.setStatus('up-to-date', { version: this.version });
    });
    this.updater.on('download-progress', progress => {
      this.setStatus('downloading', {
        percent: clampNumber(progress?.percent, 0, 100),
        transferred: safeCount(progress?.transferred),
        total: safeCount(progress?.total)
      });
    });
    this.updater.on('update-downloaded', info => {
      this.downloaded = true;
      this.version = safeVersion(info?.version);
      this.setStatus('downloaded', { version: this.version });
    });
    this.updater.on('error', () => {
      this.setStatus('error', { message: 'No se pudo verificar o descargar la actualización firmada.' });
    });
  }

  async check() {
    if (!this.updater) return this.publicState('Las actualizaciones no están disponibles en esta compilación.');
    if (this.status === 'checking' || this.status === 'downloading') return this.publicState();
    await this.updater.checkForUpdates();
    return this.publicState();
  }

  canInstall() { return Boolean(this.updater && this.downloaded && !this.isBusy()); }

  installNow() {
    if (!this.updater || !this.downloaded) throw operationError('UPDATE_NOT_READY', 'La actualización aún no está preparada.');
    if (this.isBusy()) throw operationError('APP_BUSY', 'Espera a que termine el análisis o la operación de cuarentena.');
    this.updater.quitAndInstall(false, true);
  }

  publicState(message) {
    return {
      status: this.status,
      currentVersion: this.app.getVersion(),
      version: this.version,
      canInstall: this.canInstall(),
      message
    };
  }

  setStatus(status, details = {}) {
    this.status = status;
    const eventType = ({
      available: 'update-available',
      downloading: 'update-progress',
      downloaded: 'update-downloaded',
      error: 'update-error',
      'up-to-date': 'update-not-available',
      checking: 'update-checking'
    })[status];
    if (eventType) this.publish({ type: eventType, ...details });
  }
}

function safeVersion(value) {
  const text = String(value ?? '');
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(text) ? text : undefined;
}

function safeCount(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.min(number, Number.MAX_SAFE_INTEGER) : 0;
}

function clampNumber(value, minimum, maximum) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(maximum, Math.max(minimum, number)) : minimum;
}

function operationError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
