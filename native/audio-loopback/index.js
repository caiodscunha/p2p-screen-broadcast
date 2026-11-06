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
      // Binário compilado antes dessa função existir não a tem — sem ela só
      // não dá pra desligar a política de segundo plano, o resto funciona.
      disableProcessThrottling: addon.disableProcessThrottling
        ? (pid) => addon.disableProcessThrottling(pid)
        : null,
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

// Mata processos auxiliares que sobraram de uma execução anterior que caiu
// sem limpar (só existe no Linux — ver linux-pipewire.js).
function cleanupOrphans() {
  if (backend && backend.cleanupOrphans) backend.cleanupOrphans();
}

// Windows: pede ao SO pra NÃO tratar o processo `pid` como "de segundo plano"
// (EcoQoS + núcleos de eficiência + timer mais grosso quando a janela é
// minimizada) — ver DisableProcessThrottling em src/process_loopback.cpp pro
// porquê. Devolve true se aplicou. Em outros SOs (ou sem o addon) não faz
// nada e devolve false. Funciona mesmo sem a captura de áudio por processo
// estar disponível, desde que o addon tenha carregado.
function disableProcessThrottling(pid) {
  if (!backend || !backend.disableProcessThrottling) return false;
  try {
    return Boolean(backend.disableProcessThrottling(pid));
  } catch {
    return false;
  }
}

module.exports = { supported, listProcesses, startCapture, stopCapture, cleanupOrphans, disableProcessThrottling };
