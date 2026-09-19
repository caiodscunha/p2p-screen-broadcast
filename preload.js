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

  // Canal de sinalização sem servidor (UDP+STUN+UPnP+ntfy, ver
  // signal-punch.js) — usado pra entrar numa sala e depois formar a malha de
  // conexões WebRTC entre todo mundo (ver protocolo em renderer.js).
  startSignalListener: () => ipcRenderer.invoke('signal:startListener'),
  stopSignalListener: (sessionId) => ipcRenderer.invoke('signal:stopListener', sessionId),
  sendSignalMessage: (info) => ipcRenderer.invoke('signal:send', info),
  onSignalMessage: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on('signal:message', listener);
    return () => ipcRenderer.removeListener('signal:message', listener);
  },
});
