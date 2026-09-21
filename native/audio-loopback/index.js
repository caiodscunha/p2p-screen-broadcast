'use strict';

const path = require('path');

// Windows usa o addon nativo em src/ (WASAPI Process Loopback). Linux usa
// ferramentas de linha de comando do PipeWire em vez de addon nativo (ver
// linux-pipewire.js) — não existe binding C++ nem WASAPI equivalente
// portável entre distros. macOS não tem nenhum dos dois ainda.
let backend = null;
if (process.platform === 'win32') {
  try {
    const addon = require(path.join(__dirname, 'build', 'Release', 'audio_loopback.node'));
    backend = {
      supported: true,
      listProcesses: () => addon.listProcesses(),
      startCapture: (pid, exclude, callback) => addon.startCapture(pid, exclude, callback),
      stopCapture: (handle) => addon.stopCapture(handle),
    };
  } catch {
    // Addon não compilado/disponível — o app segue funcionando sem esse recurso.
    backend = null;
  }
} else if (process.platform === 'linux') {
  backend = require('./linux-pipewire');
}

const supported = Boolean(backend && backend.supported);

function listProcesses() {
  if (!supported) return [];
  return backend.listProcesses();
}

// callback(error, samples, sampleRate, channels) — error é string|null.
// Pode retornar o handle direto (Windows) ou uma Promise<handle> (Linux) —
// quem chama deve dar await no resultado, o que funciona nos dois casos.
function startCapture(pid, exclude, callback) {
  if (!supported) throw new Error('Captura de áudio por processo não está disponível nesta plataforma/build.');
  return backend.startCapture(pid, exclude, callback);
}

function stopCapture(handle) {
  if (!backend) return;
  backend.stopCapture(handle);
}

module.exports = { supported, listProcesses, startCapture, stopCapture };
