const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  copyToClipboard: (text) => ipcRenderer.invoke('clipboard:write', text),
  readClipboard: () => ipcRenderer.invoke('clipboard:read'),
  supportsSystemAudio: () => ipcRenderer.invoke('capture:supportsSystemAudio'),
  listScreens: () => ipcRenderer.invoke('capture:listScreens'),

  // Captura de áudio por processo (só Windows) — deixa incluir só um app
  // específico, ou excluir um app específico do resto.
  supportsProcessAudio: () => ipcRenderer.invoke('audio-process:supported'),
  listAudioProcesses: () => ipcRenderer.invoke('audio-process:list'),
  startProcessAudioCapture: (pid, exclude) => ipcRenderer.invoke('audio-process:start', { pid, exclude }),
  stopProcessAudioCapture: (handle) => ipcRenderer.invoke('audio-process:stop', handle),
  onProcessAudioChunk: (callback) => {
    const listener = (event, samples, sampleRate, channels) => callback(samples, sampleRate, channels);
    ipcRenderer.on('audio-process:chunk', listener);
    return () => ipcRenderer.removeListener('audio-process:chunk', listener);
  },
  onProcessAudioError: (callback) => {
    const listener = (event, message) => callback(message);
    ipcRenderer.on('audio-process:error', listener);
    return () => ipcRenderer.removeListener('audio-process:error', listener);
  },

  // Handshake automático de resposta (UDP+STUN, ver signal-punch.js) — os
  // candidatos vão embutidos no próprio código de oferta, ver renderer.js.
  startHostSignal: () => ipcRenderer.invoke('signal:startHost'),
  stopHostSignal: (sessionId) => ipcRenderer.invoke('signal:stopHost', sessionId),
  sendSignalAnswer: (info) => ipcRenderer.invoke('signal:sendAnswer', info),
  onSignalAnswer: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on('signal:answer', listener);
    return () => ipcRenderer.removeListener('signal:answer', listener);
  },
});
