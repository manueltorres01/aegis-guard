'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// Sandboxed preloads intentionally cannot require local modules. Keep this tiny
// allowlist in sync with IPC_CHANNELS in ipc-contracts.mjs.
const CHANNELS = Object.freeze({
  bootstrap: 'aegis:bootstrap',
  chooseScanTarget: 'aegis:target:choose',
  startScan: 'aegis:scan:start',
  cancelScan: 'aegis:scan:cancel',
  listQuarantine: 'aegis:quarantine:list',
  quarantineIsolate: 'aegis:quarantine:isolate',
  restoreQuarantine: 'aegis:quarantine:restore',
  startMonitor: 'aegis:monitor:start',
  stopMonitor: 'aegis:monitor:stop',
  pauseProtection: 'aegis:protection:pause',
  resumeProtection: 'aegis:protection:resume',
  saveSettings: 'aegis:settings:save',
  createAndScanSimulation: 'aegis:simulation:run',
  checkForUpdates: 'aegis:update:check',
  installUpdate: 'aegis:update:install',
  event: 'aegis:event'
});

const invokeWithoutPayload = channel => () => ipcRenderer.invoke(channel);

const api = {
  getBootstrap: invokeWithoutPayload(CHANNELS.bootstrap),
  chooseScanTarget: options => ipcRenderer.invoke(CHANNELS.chooseScanTarget, options),
  startScan: options => ipcRenderer.invoke(CHANNELS.startScan, options),
  cancelScan: invokeWithoutPayload(CHANNELS.cancelScan),
  listQuarantine: invokeWithoutPayload(CHANNELS.listQuarantine),
  isolateResult: request => ipcRenderer.invoke(CHANNELS.quarantineIsolate, request),
  restoreQuarantine: request => ipcRenderer.invoke(CHANNELS.restoreQuarantine, request),
  startMonitor: request => ipcRenderer.invoke(CHANNELS.startMonitor, request),
  stopMonitor: invokeWithoutPayload(CHANNELS.stopMonitor),
  pauseProtection: invokeWithoutPayload(CHANNELS.pauseProtection),
  resumeProtection: invokeWithoutPayload(CHANNELS.resumeProtection),
  saveSettings: settings => ipcRenderer.invoke(CHANNELS.saveSettings, settings),
  createAndScanSimulation: invokeWithoutPayload(CHANNELS.createAndScanSimulation),
  checkForUpdates: invokeWithoutPayload(CHANNELS.checkForUpdates),
  restartAndUpdate: invokeWithoutPayload(CHANNELS.installUpdate),
  onEvent(callback) {
    if (typeof callback !== 'function') throw new TypeError('onEvent requires a function');
    const listener = (_event, applicationEvent) => callback(applicationEvent);
    ipcRenderer.on(CHANNELS.event, listener);
    return () => ipcRenderer.removeListener(CHANNELS.event, listener);
  }
};

contextBridge.exposeInMainWorld('aegis', Object.freeze(api));
