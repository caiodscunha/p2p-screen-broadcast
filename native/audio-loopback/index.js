'use strict';

const path = require('path');

let addon = null;
if (process.platform === 'win32') {
  try {
    addon = require(path.join(__dirname, 'build', 'Release', 'audio_loopback.node'));
  } catch (err) {
    // Addon não compilado/disponível — o app segue funcionando sem esse recurso.
    addon = null;
  }
}

const supported = Boolean(addon);

function listProcesses() {
  if (!addon) return [];
  return addon.listProcesses();
}

// callback(error, samples, sampleRate, channels) — error é string|null
function startCapture(pid, exclude, callback) {
  if (!addon) throw new Error('Captura de áudio por processo não está disponível nesta plataforma/build.');
  return addon.startCapture(pid, exclude, callback);
}

function stopCapture(handle) {
  if (!addon) return;
  addon.stopCapture(handle);
}

module.exports = { supported, listProcesses, startCapture, stopCapture };
