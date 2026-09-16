const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  copyToClipboard: (text) => ipcRenderer.invoke('clipboard:write', text),
  readClipboard: () => ipcRenderer.invoke('clipboard:read'),
  supportsSystemAudio: () => ipcRenderer.invoke('capture:supportsSystemAudio'),
  notifyCaptureStarted: () => ipcRenderer.invoke('capture:started'),
});
